Add execution permissions on the scripts you want to run cd installers/<CLOUD_TYPE> for example "cd installers/gcs" for GCS chmod +x setup_gcs_file_notification.sh - for GCS chmod +x setup_azure_file_notification.sh - for Azure chmod +x setup_s3_file_notification.sh - for S3/AWS

Run as below cd installers/<CLOUD_TYPE> for example "cd installers/gcs" for GCS

./setup_gcs_file_notification.sh input_parameters_gcs.conf - For GCS file notification pipeline setup
./setup_azure_file_notification.sh input_parameters_azure.conf - For Azure file notification pipeline setup
./setup_s3_file_notification.sh input_parameters_s3.conf - For S3 file notification pipeline setup
Note:

Make sure to keep both script file (sh) and conf file (input file) in the same folder,
For gcs setup, make sure to have secrete manager access to the gcs project