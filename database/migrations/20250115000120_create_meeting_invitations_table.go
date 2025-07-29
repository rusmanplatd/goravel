package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000120CreateMeetingInvitationsTable struct{}

// Signature The name and signature of the console command.
func (r *M20250115000120CreateMeetingInvitationsTable) Signature() string {
	return "20250115000120_create_meeting_invitations_table"
}

// Up Run the migrations.
func (r *M20250115000120CreateMeetingInvitationsTable) Up() error {
	return facades.Schema().Create("meeting_invitations", func(table schema.Blueprint) {
		table.ID()
		table.String("meeting_id").Comment("Meeting ID that this invitation is for")
		table.String("sent_by").Comment("User ID who sent the invitation")
		table.String("recipient_id").Nullable().Comment("Recipient user ID (for internal users)")
		table.String("email").Nullable().Comment("Recipient email address (for external users)")
		table.String("display_name").Nullable().Comment("Display name of the recipient")
		table.String("role").Default("attendee").Comment("Role for the invitation")
		table.String("status").Default("sent").Comment("Invitation status")
		table.Text("custom_message").Nullable().Comment("Custom message included with the invitation")
		table.Text("response_message").Nullable().Comment("Response message from the recipient")
		table.TimestampTz("sent_at").Nullable().Comment("When the invitation was sent")
		table.TimestampTz("responded_at").Nullable().Comment("When the recipient responded")
		table.TimestampTz("expires_at").Nullable().Comment("Invitation expiry time")
		table.Boolean("calendar_invitation_sent").Default(false).Comment("Whether calendar invitation was sent")
		table.Boolean("email_notification_sent").Default(false).Comment("Whether email notification was sent")
		table.Integer("reminders_sent").Default(0).Comment("Number of reminder emails sent")
		table.Json("metadata").Nullable().Comment("Additional metadata for the invitation")
		table.Timestamps()

		// Indexes for performance
		table.Index("meeting_id")
		table.Index("sent_by")
		table.Index("recipient_id")
		table.Index("email")
		table.Index("status")
		table.Index("sent_at")
		table.Index("expires_at")
	})
}

// Down Reverse the migrations.
func (r *M20250115000120CreateMeetingInvitationsTable) Down() error {
	return facades.Schema().DropIfExists("meeting_invitations")
}
