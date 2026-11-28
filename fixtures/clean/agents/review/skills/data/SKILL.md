---
name: data
description: Fetches data.
---
aws --profile prod s3 cp "s3://acme-data/train.csv" ./train.csv
gsutil -m cp gs://acme-models/m.bin ./m.bin
```sh
aws s3 \
  cp s3://acme-data/x.csv ./x.csv
```
