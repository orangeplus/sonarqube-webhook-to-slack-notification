# sonarqube-webhook-to-slack-notification
Small web service that takes a api token authenticated standard SonarQube cloud webhook and sends it as a slack notification

Requires two environmental variables

SLACK_WEBHOOK_URL

https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/

WEBHOOK_API_KEY

This value is required, any text entered here must also be configured as the API Key on the Sonarqube site
