package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/iann0036/iamlive/iamlivecore"
	"github.com/ryanjarv/goutil/utils"
	"github.com/ryanjarv/sqs/cmd/events/entities/tmphack"
	"github.com/ryanjarv/sqs/types"
	"io"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"
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
		_, _ = fmt.Fprintln(w, "Usage of principals:")
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
	ct := NewPrincipals(ctx, in)

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

func NewPrincipals(ctx utils.Context, r io.ReadCloser) *Principals {
	pipe, writer := io.Pipe()

	c := &Principals{
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

type Principals struct {
	*io.PipeReader
	in            *bufio.Reader
	out           *io.PipeWriter
	ctx           utils.Context
	Sessions      *sync.Map
	sessionTokens map[string]bool
}

func (c *Principals) run() error {
	defer c.out.Close()

	scanner := bufio.NewScanner(c.in)

	for scanner.Scan() {
		line := scanner.Bytes()

		// Skip blank lines
		if len(line) == 0 {
			continue
		}
		var data types.GenericEvent
		err := json.Unmarshal(line, &data)
		if err != nil {
			c.ctx.Debug.Printf("cloudtrail: failed to unmarshal: %b", line)
			return fmt.Errorf("failed to unmarshal: %s", err)
		}

		var event types.AssumeRoleEvent
		err = json.Unmarshal(line, &event)
		if err != nil {
			c.ctx.Debug.Printf("cloudtrail: failed to unmarshal: %b", line)
			return fmt.Errorf("failed to unmarshal: %s", err)
		}

		data["__context__"] = c.enrich(event, data)

		b, err := json.Marshal(data)
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

func (c *Principals) enrich(event types.AssumeRoleEvent, data types.GenericEvent) types.Context {
	resp := types.Context{}

	var err error
	resp.Entities.Current, err = event.UserIdentity.EntityId()
	if err != nil {
		c.ctx.Error.Println("principals: enrich: %w", err)
	}

	//resp.Entities.Target = event.EntityTarget()
	//c.ctx.Debug.Printf("entity result: %+v\n", resp.Context.Entities)

	svcs := ReadServiceFiles()
	resp.Statements = discoverResources(svcs, event, data)

	return resp
}

func discoverResources(svcs map[string]iamlivecore.ServiceDefinition, event types.AssumeRoleEvent, data types.GenericEvent) []iamlivecore.Statement {
	svcPrefix := strings.Split(event.EventSource, ".")[0]
	svc := svcs[svcPrefix]
	op := svc.Operations[event.EventName]

	params := map[string][]string{}
	err := tmphack.Flatten(true, params, data["requestParameters"], "")
	if err != nil {
		log.Fatalln(err)
	}

	if op.Input.Type == "structure" {
		params = normalize(params, op, svc)
	}

	entry := tmphack.Entry{
		Region:  event.AwsRegion,
		Service: svc.Metadata.ServiceID,

		// Think there's something else going on to determine this
		// we're trying to find the best match and fill the shape?
		Method: event.EventName,

		Parameters:          params,
		URIParameters:       nil,
		FinalHTTPStatusCode: 200,
	}

	return tmphack.GetStatementsForProxyCall(entry)
}

func normalize(params map[string][]string, op iamlivecore.ServiceOperation, svc iamlivecore.ServiceDefinition) map[string][]string {
	for k, v := range params {
		if k != "Action" && k != "Version" {
			normalizedK := regexp.MustCompile(`\.member\.[0-9]+`).ReplaceAllString(k, "[]")
			normalizedK = regexp.MustCompile(`\.[0-9]+`).ReplaceAllString(normalizedK, "[]")

			resolvedPropertyName := tmphack.ResolvePropertyName(op.Input, normalizedK, "", "", svc.Shapes)
			if resolvedPropertyName != "" {
				normalizedK = resolvedPropertyName
			}

			if len(params[normalizedK]) > 0 {
				params[normalizedK] = append(params[normalizedK], v...)
			} else {
				params[normalizedK] = v
			}
		}
	}
	return params
}

func ReadServiceFiles() map[string]iamlivecore.ServiceDefinition {
	resp := map[string]iamlivecore.ServiceDefinition{}
	tmphack.LoadMaps()

	files, err := tmphack.ServiceFiles.ReadDir("service")
	if err != nil {
		panic(err)
	}

	for _, dirEntry := range files {
		file, err := tmphack.ServiceFiles.Open("service/" + dirEntry.Name())
		if err != nil {
			panic(err)
		}

		data, err := ioutil.ReadAll(file)
		if err != nil {
			panic(err)
		}

		var def iamlivecore.ServiceDefinition
		if json.Unmarshal(data, &def) != nil {
			panic(err)
		}

		resp[def.Metadata.EndpointPrefix] = def
	}
	return resp
}
