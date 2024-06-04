Run as below 

cd windows_installers/<CLOUD_TYPE> for example "cd windows_installers/gcs" for GCS

#run this file with command ".\setup_gcs_file_notification_windows.ps1 -ConfigFile input_parameters_gcs_windows.txt" - For GCS file notification pipeline setup

#run this file with command ".\setup_azure_file_notification_windows.ps1 -ConfigFile input_parameters_azure_windows.txt"m- For Azure file notification pipeline setup

#run this file with command ".\setup_s3_file_notification_windows.ps1 -ConfigFile input_parameters_s3_windows.txt" - For S3 file notification pipeline setup

Note:

Make sure to keep both script file (sh) and conf file (input file) in the same folder,
For gcs setup, make sure to have secrete manager access to the gcs project