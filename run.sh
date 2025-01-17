#!/bin/bash

#export MINIO_ENDPOINT=""
#export MINIO_REGION=""
#export MINIO_ACCESS_KEY=""
#export MINIO_SECRET_KEY=""
#export MINIO_BUCKET_NAME="ltnudp"

sudo ./target/debug/udp_to_s3 --address 227.1.20.90 --port 4010 --interface eno2 --verbose 2
