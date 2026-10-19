$ErrorActionPreference = "Stop"

docker exec sih-kafka /opt/kafka/bin/kafka-topics.sh `
  --bootstrap-server localhost:9092 `
  --create `
  --if-not-exists `
  --topic zeek-events `
  --partitions 3 `
  --replication-factor 1

Write-Host "Topic zeek-events is ready."
