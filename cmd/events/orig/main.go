package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/ryanjarv/goutil/utils"
	"github.com/ryanjarv/sqs/types"
	"io"
	"os"
	"sync"
)

type Args struct {
	Debug bool
}

func main() {
	ctx := utils.NewContext(context.Background(), true)

	args := Args{}

	flag.Usage = func() {
		w := flag.CommandLine.Output() // may be os.Stderr - but not necessarily
		_, _ = fmt.Fprintln(w, "Usage of ctnorm:")
		flag.PrintDefaults()
		_, _ = fmt.Fprintln(w, `TODO`)
	}

	flag.BoolVar(&args.Debug, "debug", false, "Enable debug output")
	flag.Parse()

	if args.Debug {
		ctx.SetLoggingLevel(utils.DebugLogLevel)
	}

	if len(flag.Args()) > 1 {
		ctx.Error.Fatalln("extra arguments detected, did you mean to pass a comma seperated list to -profiles instead?")
	}

	err := Run(ctx, flag.Arg(0))
	if err != nil {
		ctx.Error.Fatalln(err)
	}
}

func Run(ctx utils.Context, path string) error {
	var in io.ReadCloser

	if path == "" || path == "-" {
		in = os.Stdin
	} else {
		var err error
		in, err = os.Open(path)
		if err != nil {
			return fmt.Errorf("opening %s: %w", path, err)
		}
	}
	ct := NewCloudTrail(ctx, in)

	var err error
	go func() {
		<-ctx.Done()
		err := ct.Close()
		if err != nil {
			ctx.Error.Println("run: closing cloudtrail stream: %s")
		}
	}()

	_, err = io.Copy(os.Stdout, ct)
	if err != nil {
		return fmt.Errorf("run: copy to stdout: %w", err)
	}
	return nil
}

func NewCloudTrail(ctx utils.Context, r io.ReadCloser) *CloudTrail {
	pipe, writer := io.Pipe()

	c := &CloudTrail{
		PipeReader:    pipe,
		in:            bufio.NewReader(r),
		out:           writer,
		ctx:           ctx,
		Sessions:      &sync.Map{},
		sessionTokens: map[string]bool{},
	}

	go func() {
		err := c.run()
		if err != nil {
			ctx.Error.Println("cloudtrail: run:", err)
			ctx.Cancel()
		}
	}()

	return c
}

type CloudTrail struct {
	*io.PipeReader
	in            *bufio.Reader
	out           *io.PipeWriter
	ctx           utils.Context
	Sessions      *sync.Map
	sessionTokens map[string]bool
}

func (c *CloudTrail) run() error {
	defer c.out.Close()

	scanner := bufio.NewScanner(c.in)

	for scanner.Scan() {
		line := scanner.Bytes()

		// Skip blank lines
		if len(line) == 0 {
			continue
		}

		var event types.AssumeRoleEvent
		err := json.Unmarshal(line, &event)

		if err != nil {
			c.ctx.Debug.Printf("cloudtrail: failed to unmarshal: %b", line)
			return fmt.Errorf("failed to unmarshal: %s", err)
		}

		enriched := c.enrich(event)
		b, err := json.Marshal(enriched)
		if err != nil {
			c.ctx.Debug.Printf("cloudtrail: failed to marshal: %+v", event)
			return fmt.Errorf("failed to marshal: %w", err)
		}
		_, err = c.out.Write(append(b, '\n'))
		if err != nil {
			return fmt.Errorf("writing to output: %w", err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading standard input: %w", err)
	}
	return nil
}

type EnrichedEvent struct {
	types.AssumeRoleEvent
	OriginalUserIdentity interface{}
}

func (c *CloudTrail) enrich(event types.AssumeRoleEvent) EnrichedEvent {
	userId := event.UserIdentity.Id()
	c.ctx.Debug.Printf("enrich: event id: %s\n", userId)

	resp := EnrichedEvent{AssumeRoleEvent: event}
	value, loaded := c.Sessions.Load(userId)
	if loaded {
		resp.OriginalUserIdentity = value.(types.UserIdentity)
	}

	//if event.ErrorCode != "" || !utils.In([]string{"AWSService", "AssumedRole"}, event.UserIdentity.Type) {
	//	return EnrichedEvent{AssumeRoleEvent: event}
	//}

	// TODO: check other event types
	if event.EventType == "AwsApiCall" {
		if t := event.Target(); t != nil {
			c.ctx.Debug.Printf("enrich: new identity: %s -> %s\n", userId, t.Id())
			_, loaded := c.Sessions.LoadOrStore(t.Id(), event.UserIdentity)

			if loaded {
				// If we've already seen this session token it's likely just a duplicate record.
				if _, ok := c.sessionTokens[event.ResponseElements.Credentials.SessionToken]; ok {
					c.ctx.Info.Println("duplicate session token found:", t.Id())
				} else {
					// In the case that we haven't, it's possible that a collision occurred.
					//
					// It is possible for two sessions to end up with the same set of identifiable userIdentity records.
					// This *should* be rare, but it is worth investigating if it happens.
					//
					// More likely than not it's just a bug though.
					c.ctx.Error.Fatalln("target id collision:", t.Id())
				}
			}
			c.sessionTokens[event.ResponseElements.Credentials.SessionToken] = true
		}
	}

	return resp
}

//func (c *CloudTrail) Close() error {
//	c.out.
//}
