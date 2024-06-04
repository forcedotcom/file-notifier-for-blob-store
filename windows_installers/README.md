Run as below 

Open the powershell command as "run as administrator"

#Run "Set-ExecutionPolicy Unrestricted" in the powershell terminal

cd windows_installers/<CLOUD_TYPE> for example "cd windows_installers/gcs" for GCS

#run this file with command ".\setup_gcs_file_notification_windows.ps1 -ConfigFile input_parameters_gcs_windows.txt" - For GCS file notification pipeline setup

#run this file with command ".\setup_azure_file_notification_windows.ps1 -ConfigFile input_parameters_azure_windows.txt" - For Azure file notification pipeline setup

#run this file with command ".\setup_s3_file_notification_windows.ps1 -ConfigFile input_parameters_s3_windows.txt" - For S3 file notification pipeline setup

Note:

Make sure to keep both powershell file (ps1) and conf file (input file) in the same folder,
For gcs setup, make sure to have secrete manager access to the gcs project
For s3/aws setup, make sure to have AWS_ACCESS_KEY, AWS_SECRETE_ACCESS_KEY, AWS_SESSION_TOKEN with admin access set as environment variables in the powershell terminal