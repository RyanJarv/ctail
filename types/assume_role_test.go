package types

import (
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/ryanjarv/sqs/schema/aws/logs/awsapicallviacloudtrail"
	"reflect"
	"testing"
	"time"
)


var testDate = time.Date(2022, time.April, 1, 1, 1, 1, 1, &time.Location{})

func TestAssumeRoleIdentity_Id(t *testing.T) {
	type fields struct {
		Type           string
		InvokedBy      string
		PrincipalId    string
		Arn            string
		UserName       string
		AccountId      string
		AccessKeyId    string
		SessionContext *awsapicallviacloudtrail.SessionContext
	}
	tests := []struct {
		name   string
		fields UserIdentity
		want   string
	}{
		{
			name: "AWSService",
			fields: UserIdentity{
				Type:      "AWSService",
				InvokedBy: "codepipeline.amazonaws.com",
			},
			want: "AWSService:codepipeline.amazonaws.com",
		},
		{
			name: "AWSAccount",
			fields: UserIdentity{
				Type:        "AWSAccount",
				AccountId:   "123456789012",
				PrincipalId: "AIDA33333333333333333:test",
			},
			want: fmt.Sprintf("AWSAccount:123456789012:AIDA33333333333333333:test"),
		},
		{
			name: "AssumedRole",
			fields: UserIdentity{
				Type:        "AssumedRole",
				InvokedBy:   "",
				Arn:         "arn:aws:sts::111111111111:assumed-role/new-sar/swards",
				AccessKeyId: "ASIA4444444444444444",
				SessionContext: &awsapicallviacloudtrail.SessionContext{
					Attributes: awsapicallviacloudtrail.Attributes{
						CreationDate: testDate,
					},
				},
			},
			want: fmt.Sprintf("AssumedRole::arn:aws:sts::111111111111:assumed-role/new-sar/swards:ASIA4444444444444444:%d", testDate.Unix()),
		},
		{
			name: "FederatedUser",
			fields: UserIdentity{
				Type:        "FederatedUser",
				Arn:         "arn:aws:sts::111111111111:federated-user/test",
				AccessKeyId: "ASIA2222222222222222",
				SessionContext: &awsapicallviacloudtrail.SessionContext{
					Attributes: awsapicallviacloudtrail.Attributes{
						CreationDate: testDate,
					},
				},
			},
			want: fmt.Sprintf("FederatedUser::arn:aws:sts::111111111111:federated-user/test:ASIA2222222222222222:1648774861"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.fields.Id(); got != tt.want {
				t.Errorf("Id() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAssumeRoleEvent_Target(t *testing.T) {
	tests := []struct {
		name  string
		event AssumeRoleEvent
		want  *UserIdentity
	}{
		{
			name: "AssumeRole",
			event: AssumeRoleEvent{
				EventName: "AssumeRole",
				EventTime: testDate,
				RequestParameters: RequestParameters{
					RoleSessionName: "AWSCodeBuild-11111111-1111-1111-1111-111111111111",
				},
				ResponseElements: ResponseElements{
					AssumedRoleUser: &AssumeRoleUser{
						Arn: "arn:aws:iam::222222222222:role/simulate-user-activity-role",
					},
					Credentials: &Credentials{
						AccessKeyId: "ASIA1111111111111111",
					},
				},
			},
			want: &UserIdentity{
				Type:        "AssumedRole",
				Arn:         "arn:aws:iam::222222222222:role/simulate-user-activity-role",
				AccessKeyId: "ASIA1111111111111111",
				SessionContext: &awsapicallviacloudtrail.SessionContext{
					Attributes: awsapicallviacloudtrail.Attributes{
						CreationDate: testDate,
					},
				},
			},
		},
		{
			name: "GetFederationToken",
			event: AssumeRoleEvent{
				EventName: "GetFederationToken",
				EventTime: testDate,
				RequestParameters: RequestParameters{
					Name: "name",
				},
				ResponseElements: ResponseElements{
					Credentials: &Credentials{
						AccessKeyId: "ASIA2222222222222222",
					},
					FederatedUser: &FederatedUser{
						Arn: "arn:aws:sts::111111111111:federated-user/test",
					},
				},
			},
			want: &UserIdentity{
				Type:        "FederatedUser",
				Arn:         "arn:aws:sts::111111111111:federated-user/test",
				AccessKeyId: "ASIA2222222222222222",
				SessionContext: &awsapicallviacloudtrail.SessionContext{
					Attributes: awsapicallviacloudtrail.Attributes{
						CreationDate: testDate,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.event.Target()
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("MakeGatewayInfo() mismatch (-want +got):\n%s", diff)
			}
		})

		// Ensure the source target id matches the resulting sessions identity id.
		t.Run(tt.name+"_source_id_matches_resulting_session_id", func(t *testing.T) {
			if got := tt.event.Target().Id(); !reflect.DeepEqual(got, tt.want.Id()) {
				t.Errorf("Target() = %v, want %v", got, tt.want)
			}
		})
	}
}
