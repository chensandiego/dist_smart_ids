
import boto3
import json
import time
from datetime import datetime, timedelta

# Configure your AWS credentials and region
AWS_REGION = "us-east-1"
POLL_INTERVAL = 300  # 5 minutes

def get_cloudtrail_client():
    """Creates and returns a CloudTrail client."""
    return boto3.client("cloudtrail", region_name=AWS_REGION)

def fetch_cloudtrail_events(client, start_time):
    """Fetches CloudTrail events from the specified start time."""
    return client.lookup_events(
        LookupAttributes=[{"AttributeKey": "EventTime", "AttributeValue": start_time.isoformat()}],
        MaxResults=50
    )

def analyze_event(event):
    """Analyzes a single CloudTrail event for suspicious activity."""
    event_name = event.get("EventName")
    user_identity = event.get("Username")
    
    # Example rule: Alert on security group changes
    if event_name in ["AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress"]:
        print(f"Suspicious activity detected: {event_name} by {user_identity}")
        # In a real implementation, you would send an alert to the aggregator
        
    # Example rule: Alert on IAM user creation
    if event_name == "CreateUser":
        print(f"Suspicious activity detected: New IAM user created by {user_identity}")

def main():
    """Main function to poll CloudTrail events."""
    client = get_cloudtrail_client()
    
    while True:
        start_time = datetime.utcnow() - timedelta(seconds=POLL_INTERVAL)
        print(f"Fetching CloudTrail events from {start_time}...")
        
        try:
            response = fetch_cloudtrail_events(client, start_time)
            events = response.get("Events", [])
            
            for event in events:
                analyze_event(event)
                
        except Exception as e:
            print(f"Error fetching or analyzing CloudTrail events: {e}")
            
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
