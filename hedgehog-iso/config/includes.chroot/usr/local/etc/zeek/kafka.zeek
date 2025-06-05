global zeek_kafka_enabled = (getenv("ZEEK_KAFKA_ENABLED") == true_regex) ? T : F;
global zeek_kafka_brokers = getenv("ZEEK_KAFKA_BROKERS");
global zeek_kafka_topic = getenv("ZEEK_KAFKA_TOPIC");

@if (zeek_kafka_enabled)
 @load packages/zeek-kafka
 redef Kafka::send_all_active_logs = T;
 redef Kafka::topic_name = zeek_kafka_topic;
 redef Kafka::tag_json = T;
 redef Kafka::kafka_conf = table(
     ["metadata.broker.list"] = zeek_kafka_brokers
);
@endif
