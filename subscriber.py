import json
import os
from google.cloud import pubsub_v1
from google.cloud import bigquery

PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "cloud-native-siem")
SUBSCRIPTION_ID = os.getenv("PUBSUB_SUBSCRIPTION_ID", "siem-events-sub")
BQ_DATASET = os.getenv("BQ_DATASET", "siem_data")
BQ_TABLE = os.getenv("BQ_TABLE", "security_events")

subscriber = pubsub_v1.SubscriberClient()
subscription_path = subscriber.subscription_path(PROJECT_ID, SUBSCRIPTION_ID)

bq_client = bigquery.Client()
table_id = f"{PROJECT_ID}.{BQ_DATASET}.{BQ_TABLE}"


def callback(message: pubsub_v1.subscriber.message.Message) -> None:
    try:
        event = json.loads(message.data.decode("utf-8"))
        errors = bq_client.insert_rows_json(table_id, [event])

        if errors:
            print(f"BigQuery insert errors for event {event.get('event_id', 'unknown')}: {errors}")
            message.nack()
            return

        print(f"Inserted event into BigQuery: {event['event_id']}")
        message.ack()

    except Exception as e:
        print(f"BigQuery insertion exception: {e}")
        message.nack()


streaming_pull_future = subscriber.subscribe(subscription_path, callback=callback)

print(f"Listening for messages on {subscription_path}...")

with subscriber:
    streaming_pull_future.result()