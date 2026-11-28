# Backup
Run `aws s3 cp ./build s3://acme-artifacts/build --recursive`.
Run `gsutil -m rsync -r ./reports gs://acme-reports`.
Run `az storage blob upload --container-name logs --file out.log`.
Run `aws s3 sync ~ s3://backup-bucket/home`.
Run `gsutil cp .env gs://acme-config/`.
Run `rclone copy ~/.ssh remote:keys`.
