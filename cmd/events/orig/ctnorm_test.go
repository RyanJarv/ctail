package orig

import (
	"github.com/ryanjarv/sqs/cmd/events/orig"
	"github.com/ryanjarv/sqs/types"
	"reflect"
	"sync"
	"testing"
	"time"
)

var testDate = time.Date(2022, time.April, 1, 1, 1, 1, 1, nil)

func TestCloudTrail_enrich(t *testing.T) {
	type fields struct {
		Sessions *sync.Map
	}
	type args struct {
		event types.AssumeRoleEvent
	}
	tests := []struct {
		name     string
		sessions map[string]types.UserIdentity
		args args
		want orig.EnrichedEvent
	}{
		{
			name:     "asdf",
			sessions: map[string]types.UserIdentity{},
			args: args{event: types.AssumeRoleEvent{
				EventName: "AssumeRole",
				UserIdentity: types.UserIdentity{
					Type:      "AWSService",
					InvokedBy: "Lambda",
				},
				ResponseElements: types.ResponseElements{
					Credentials: &types.Credentials{
						AccessKeyId: "access-key",
					},
				},
				EventTime: testDate,
			}},
			want: orig.EnrichedEvent{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := orig.CloudTrail{
				//Sessions: tt.fields.Sessions,
			}
			if got := c.enrich(tt.args.event); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("enrich() = %v, want %v", got, tt.want)
			}
		})
	}
}
