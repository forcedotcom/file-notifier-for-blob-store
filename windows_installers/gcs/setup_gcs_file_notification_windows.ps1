# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#make sure you have secrete manager access to gcp project
#edit the input_parameters_gcs_windows.txt file with respective environment variables
#on running this script, the window will be redirected to gcs portal, just login and close the window, the script will continue its execution to completion
#run this file with command ".\setup_gcs_file_notification_windows.ps1 -ConfigFile input_parameters_gcs_windows.txt"

param (
    [string] $configFile
)

# Check if the ConfigFile parameter is passed
if (-not $ConfigFile) {
    Write-Host "Error: Config file parameter is not provided."
    exit 1
}

# Check if the config file exists
if (-not (Test-Path $ConfigFile)) {
    Write-Host "Error: Config file '$ConfigFile' does not exist."
    exit 1
}

# If the script reaches this point, the config file is considered valid
Write-Host "Config file '$ConfigFile' is valid."

$configData = Get-Content -Path $configFile

# Define a hashtable to store configuration key-value pairs
$configuration = @{}

# Parse each line of the config file
foreach ($line in $configData) {
    # Skip empty lines and lines starting with #
    if (-not [string]::IsNullOrWhiteSpace($line) -and $line -notlike '#*') {
        # Split each line by the delimiter
        $key, $value = $line -split '=', 2
        # Store key-value pair in the hashtable
        $configuration[$key.Trim()] = $value.Trim()
    }
}

# Access configuration values
$PROJECT_ID = $configuration["PROJECT_ID"]
$GCS_REGION = $configuration["GCS_REGION"]
$SF_LOGIN_URL = $configuration["SF_LOGIN_URL"]
$SF_USERNAME = $configuration["SF_USERNAME"]
$EVENT_GCS_BUCKET_SOURCE = $configuration["EVENT_GCS_BUCKET_SOURCE"]
$SF_LOGIN_URL = $configuration["SF_LOGIN_URL"]
$LOCATION = $configuration["LOCATION"]
$SOURCE_CODE_BUCKET_NAME = $configuration["SOURCE_CODE_BUCKET_NAME"]
$SOURCE_CODE_LOCAL_PATH = $configuration["SOURCE_CODE_LOCAL_PATH"]
$TRIGGER_REGION = $configuration["TRIGGER_REGION"]
$CONSUMER_KEY_NAME = $configuration["CONSUMER_KEY_NAME"]
$CONSUMER_KEY_VALUE = $configuration["CONSUMER_KEY_VALUE"]
$RSA_PRIVATE_KEY_NAME = $configuration["RSA_PRIVATE_KEY_NAME"]
$PEM_FILE_PATH = $configuration["PEM_FILE_PATH"]


# Display configuration values
Write-Host "Environment Variables are set as below"
Write-Host "PROJECT_ID: $PROJECT_ID"
Write-Host "GCS_REGION: $GCS_REGION"
Write-Host "SF_LOGIN_URL: $SF_LOGIN_URL"
Write-Host "SF_USERNAME: $SF_USERNAME"
Write-Host "EVENT_GCS_BUCKET_SOURCE: $EVENT_GCS_BUCKET_SOURCE"
Write-Host "LOCATION: $LOCATION"
Write-Host "SOURCE_CODE_BUCKET_NAME: $SOURCE_CODE_BUCKET_NAME"
Write-Host "SOURCE_CODE_LOCAL_PATH: $SOURCE_CODE_LOCAL_PATH"
Write-Host "TRIGGER_REGION: $TRIGGER_REGION"
Write-Host "CONSUMER_KEY_NAME: $CONSUMER_KEY_NAME"
Write-Host "CONSUMER_KEY_VALUE: $CONSUMER_KEY_VALUE"
Write-Host "RSA_PRIVATE_KEY_NAME: $RSA_PRIVATE_KEY_NAME"
Write-Host "PEM_FILE_PATH: $PEM_FILE_PATH"

while ($true) {
    $user_input = Read-Host "Have you created connected app? (yes/no)"
    if ($user_input -eq "yes") {
        break
    }
    elseif ($user_input -eq "no") {
        Write-Host "Please create connected app before running this script"
        exit
    }
    else{
        Write-Host "Invalid input. Please enter 'yes' or 'no'."
        continue
    }
}

while ($true) {
    $user_input = Read-Host "Have you downloaded the source code for cloud function from https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/cloud_function_zips/gcp_cloud_function.zip into your local machine? (yes/no)"
    if ($user_input -eq "yes") {
        break
    }
    elseif ($user_input -eq "no") {
        Write-Host "Please download source code zip from https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/cloud_function_zips/gcp_cloud_function.zip"
        exit
    }
    else{
        Write-Host "Invalid input. Please enter 'yes' or 'no'."
        continue
    }
}

while ($true) {
    $user_input = Read-Host "As a pre-requiste you should have secretmanager access to your GCS project, do you have? (yes/no)"
    if ($user_input -eq "yes") {
        break
    }
    elseif ($user_input -eq "no") {
        Write-Host "IMPORTANT NOTE : As a pre-requiste you should have secretmanager access to your GCS project, please get the secretmanager access and then try again"
        exit
    }
    else{
        Write-Host "Invalid input. Please enter 'yes' or 'no'."
        continue
    }
}

while ($true) {
    $user_input = Read-Host "Are all the below pre-requiste steps completed?
    1. Connected app creation
    2. Downloading of gcp_cloud_function.zip
    3. Having secrete manager admin access to your gcp project
    4. Updating parameters in the configuration file input_parameters_gcs_windows.txt
    5. renaming keypair.key to keypair.pem (one of the keys generated during pre-requiste step of connected app creation)
    6. gcloud CLI and powershell installation
    (yes/no)"
    if ($user_input -eq "yes") {
        break
    }
    elseif ($user_input -eq "no") {
        Write-Host "Please complete all the mentioned pre-requiste steps before attempting to run this script"
        exit
    }
    else{
        Write-Host "Invalid input. Please enter 'yes' or 'no'."
        continue
    }
}

while ($true) {
    $user_input = Read-Host "Running this script will create new GCS bucket (if it does not exists) and set up file event notifications on it. Agree to proceed? (yes/no)"
    if ($user_input -eq "yes") {
        break
    }
    elseif ($user_input -eq "no") {
        Write-Host "Thank you"
        exit
    }
    else{
        Write-Host "Invalid input. Please enter 'yes' or 'no'."
        continue
    }
}

$gcloudPath = Get-Command gcloud -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source

if ($gcloudPath) {
    Write-Host "Google Cloud SDK (gcloud) is installed."
} else {
    Write-Host "Google Cloud SDK (gcloud) is not installed, pleasea install gcloud CLI (https://cloud.google.com/sdk/docs/install) and retry running this script"
    exit
}

$currentDateTime = Get-Date -Format "yyyyMMdd_HHmmss"
$log_filename = "logfile_$currentDateTime.txt"

Write-Host "All the gcs cloud function installer logs are logged to $log_filename file"

$validation_errors = @()

# Function to add an error to the array
function add_validation_error {
    param (
        [string] $validation_error
    )
  $Script:validation_errors += $validation_error
}

function is_valid_region {
    # Run the gcloud command to list GCS regions
    $regionsOutput = gcloud compute regions list --format="value(name)"
    $regions = $regionsOutput -split "`n" | Where-Object { $_ -ne "" }

    $valid_region_flag = $false
    foreach ($region in $regions) {
        if ($region -eq $GCS_REGION) {
            $valid_region_flag = $true
            break
        }
    }
    if($valid_region_flag){
        Write-Host "$GCS_REGION is a valid gcs region"
        "$GCS_REGION is a valid gcs region" | Out-File -FilePath $log_filename -Append
    }
    else {
        add_validation_error "Region $GCS_REGION region is invalid, please use a valid region and run 'gcloud compute regions list' to get list of valid regions"
        "Region $GCS_REGION region is invalid, please use a valid region and run 'gcloud compute regions list' to get list of valid regions" | Out-File -FilePath $log_filename -Append
    }
}

function is_valid_location {
    # Run the gcloud command to list GCS locations
    $locationsOutput = gcloud compute regions list --format="value(name)"
    $locations = $locationsOutput -split "`n" | Where-Object { $_ -ne "" }

    $valid_location_flag = $false
    foreach ($loc in $locations) {
        if ($loc -eq $LOCATION) {
            $valid_location_flag = $true
            break
        }
    }
    if($valid_location_flag){
        Write-Host "$LOCATION is a valid gcs bucket location"
        "$LOCATION is a valid gcs bucket location" | Out-File -FilePath $log_filename -Append
    }
    else {
        add_validation_error "Bucket location $LOCATION is invalid, please use a valid bucket location and run 'gcloud compute regions list' to get list of valid bucket locations"
        "Bucket location $LOCATION is invalid, please use a valid bucket location and run 'gcloud compute regions list' to get list of valid bucket locations" | Out-File -FilePath $log_filename -Append
    }
}

function is_valid_gcs_bucket_name {
    param (
        [string] $bucketName
    )

    # Check if the bucket name is between 3 and 63 characters long
    if ($bucketName.Length -lt 3 -or $bucketName.Length -gt 63) {
        return $false
    }

    # Check if the bucket name starts and ends with a number or letter
    if ($bucketName -match "^[a-z0-9].*[a-z0-9]$") {
        # Check if the bucket name contains only lowercase letters, numbers, dashes (-), and underscores (_)
        if ($bucketName -cmatch "^[a-z0-9_-]+$") {
            return $true
        }
    }

    return $false
}

function is_valid_bucket_name {
    param (
        [string] $bucketName
    )
    if (is_valid_gcs_bucket_name $bucketName) {
        Write-Host "Bucket name '$bucketName' is valid."
        "Bucket name '$bucketName' is valid." | Out-File -FilePath $log_filename -Append
    } else {
        add_validation_error "Bucket name '$bucketName' is not valid."
        "Bucket name '$bucketName' is not valid." | Out-File -FilePath $log_filename -Append
    }
}

function is_valid_source_code_local_path {

    if ($SOURCE_CODE_LOCAL_PATH -eq "" -or $SOURCE_CODE_LOCAL_PATH -eq $null) {
       add_validation_error "Error: Source code local path is missing/empty. Please provide a valid Source code local path and source code zip can be downloaded from https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/cloud_function_zips/gcp_cloud_function.zip"

       "Error: Source code local path is missing/empty. Please provide a valid Source code local path and source code zip can be downloaded from https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/cloud_function_zips/gcp_cloud_function.zip" | Out-File -FilePath $log_filename -Append
    }

    # Get the file extension
    $fileExtension = [System.IO.Path]::GetExtension($SOURCE_CODE_LOCAL_PATH)

    # Check if the file extension is ".zip"
    if ($fileExtension -eq ".zip") {
        Write-Host "SOURCE_CODE_LOCAL_PATH has a valid file of type .zip"
        "SOURCE_CODE_LOCAL_PATH has a valid file of type .zip" | Out-File -FilePath $log_filename -Append
    } else {
        add_validation_error "Error: Please include file with .zip extension for SOURCE_CODE_LOCAL_PATH"
        "Error: Please include file with .zip extension for SOURCE_CODE_LOCAL_PATH" | Out-File -FilePath $log_filename -Append
    }

    if (Test-Path $SOURCE_CODE_LOCAL_PATH -PathType Leaf) {
        Write-Host "Source code for cloud function exists at ${SOURCE_CODE_LOCAL_PATH}"
        "Source code for cloud function exists at ${SOURCE_CODE_LOCAL_PATH}" | Out-File -FilePath $log_filename -Append
    } else {
        add_validation_error "Source code for cloud function does not exists at ${SOURCE_CODE_LOCAL_PATH}"
        "Source code for cloud function does not exists at ${SOURCE_CODE_LOCAL_PATH}" | Out-File -FilePath $log_filename -Append
    }
}

function is_valid_pem_file_path {
    #validate the existance of local pem file path for adding secrete keys
    if ($PEM_FILE_PATH -eq "" -or $PEM_FILE_PATH -eq $null) {
        add_validation_error "Error: PEM_FILE_PATH - ${PEM_FILE_PATH} for creating RSA_PRIVATE_KEY does not exist or is invalid or is not of .pem type, please create it using openssl commands"

        "Error: PEM_FILE_PATH - ${PEM_FILE_PATH} for creating RSA_PRIVATE_KEY does not exist or is invalid or is not of .pem type, please create it using openssl commands" | Out-File -FilePath $log_filename -Append
    }

    if (Test-Path $PEM_FILE_PATH -PathType Leaf) {
        Write-Host "pem file exists at $PEM_FILE_PATH"
        "pem file exists at $PEM_FILE_PATH" | Out-File -FilePath $log_filename -Append
    } else {
        add_validation_error "pem file does not exists at $PEM_FILE_PATH"
        "pem file does not exists at $PEM_FILE_PATH" | Out-File -FilePath $log_filename -Append
    }

    # Get the file extension
    $fileExtension = [System.IO.Path]::GetExtension($PEM_FILE_PATH)

    # Check if the file extension is ".pem"
    if ($fileExtension -eq ".pem") {
        Write-Host "PEM_FILE_PATH has a valid file of type .pem"
        "PEM_FILE_PATH has a valid file of type .pem" | Out-File -FilePath $log_filename -Append
    } else {
        add_validation_error "Error: Please include file with .pem extension for PEM_FILE_PATH"
        "Error: Please include file with .pem extension for PEM_FILE_PATH" | Out-File -FilePath $log_filename -Append
    }
}

function is_valid_consumer_key_name {
    $pattern="^CONSUMER_KEY_[a-zA-Z0-9_-]+$"

    if($CONSUMER_KEY_NAME -match $pattern){
        Write-Host "${CONSUMER_KEY_NAME} is a valid consumer key name"
        "${CONSUMER_KEY_NAME} is a valid consumer key name" | Out-File -FilePath $log_filename -Append
    }else {
        add_validation_error "Error: The consumer key with name ${CONSUMER_KEY_NAME} does not match the pattern CONSUMER_KEY_<Your own suffix>."

        "Error: The consumer key with name ${CONSUMER_KEY_NAME} does not match the pattern CONSUMER_KEY_<Your own suffix>." | Out-File -FilePath $log_filename -Append
    }
}

function is_valid_rsa_private_key_name {
    $pattern="^RSA_PRIVATE_KEY_[a-zA-Z0-9_-]+$"

    if($RSA_PRIVATE_KEY_NAME -match $pattern){
      Write-Host "${RSA_PRIVATE_KEY_NAME} is a valid rsa private key"
      "${RSA_PRIVATE_KEY_NAME} is a valid rsa private key" | Out-File -FilePath $log_filename -Append
    }else{
      add_validation_error "Error: The rsa private key with name ${RSA_PRIVATE_KEY_NAME} does not match the pattern RSA_PRIVATE_KEY_<Your own suffix>."

      "Error: The rsa private key with name ${RSA_PRIVATE_KEY_NAME} does not match the pattern RSA_PRIVATE_KEY_<Your own suffix>." | Out-File -FilePath $log_filename -Append
    }
}

is_valid_region
is_valid_location
is_valid_bucket_name $EVENT_GCS_BUCKET_SOURCE
is_valid_bucket_name $SOURCE_CODE_BUCKET_NAME
is_valid_source_code_local_path
is_valid_pem_file_path
is_valid_consumer_key_name
is_valid_rsa_private_key_name

if ($validation_errors.Count -eq 0) {
    Write-Host "No validation errors."
    "No validation errors." | Out-File -FilePath $log_filename -Append
} else {
    Write-Host "There are validation errors as below:"
    "There are validation errors as below:" | Out-File -FilePath $log_filename -Append
    foreach ($validation_error in $validation_errors) {
        Write-Host "$validation_error"
        "$validation_error" | Out-File -FilePath $log_filename -Append
    }
    Write-Host "NOTE: Please check descriptions of each variable in https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/installers/gcs/input_parameters_gcs.conf"

    "NOTE: Please check descriptions of each variable in https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/installers/gcs/input_parameters_gcs.conf" | Out-File -FilePath $log_filename -Append

    exit
}

$FILE_NAME = Split-Path -Path $SOURCE_CODE_LOCAL_PATH -Leaf

gcloud auth login

Write-Host "Step 1/11 : Successfully logged into GCS"
"Step 1/11 : Successfully logged into GCS" | Out-File -FilePath $log_filename -Append

function IsValidGcloudProjectId {

    # Run gcloud command to describe the project
    $output = gcloud projects describe $PROJECT_ID 2>&1

    # Check if the gcloud command succeeded
    if ($LastExitCode -eq 0) {
        return $true
    } else {
        Write-Host "Error: $($output -join "`n")"
        "Error: $($output -join "`n")" | Out-File -FilePath $log_filename -Append
        return $false
    }
}

if (IsValidGcloudProjectId) {
    Write-Host "The project ID '$PROJECT_ID' is valid and exists."
    "The project ID '$PROJECT_ID' is valid and exists." | Out-File -FilePath $log_filename -Append
} else {
    Write-Host "${PROJECT_ID} does not exists or you may not have permissions to it, please use right project or create a new project"

    "${PROJECT_ID} does not exists or you may not have permissions to it, please use right project or create a new project" | Out-File -FilePath $log_filename -Append
    exit
}

gcloud config set project $PROJECT_ID

gcloud services enable pubsub.googleapis.com
gcloud services enable secretmanager.googleapis.com

function IsGcloudSecretExists {
    param (
        [string] $SecretName
    )

    # Run gcloud command to list all secrets in the project
    $output = gcloud secrets list --format="value(name)" 2>&1

    # Check if the secret exists
    if ($output -match $SecretName) {
        return $true
    } else {
        return $false
    }
}

if (IsGcloudSecretExists $CONSUMER_KEY_NAME) {
    Write-Host "Step 2/11 : Key ${CONSUMER_KEY_NAME} already exists, skipping the creation"
    "Step 2/11 : Key ${CONSUMER_KEY_NAME} already exists, skipping the creation" | Out-File -FilePath $log_filename -Append
} else {
    $CONSUMER_KEY_FILE = "consumer_key.txt"
    New-Item $CONSUMER_KEY_FILE
    Set-Content $CONSUMER_KEY_FILE $CONSUMER_KEY_VALUE
    gcloud secrets create $CONSUMER_KEY_NAME --data-file=$CONSUMER_KEY_FILE

    # Check if the secret creation was successful
    if ($LastExitCode -eq 0) {
        Write-Host "Step 2/11 : Key ${CONSUMER_KEY_NAME} creation is successfull"
        "Step 2/11 : Key ${CONSUMER_KEY_NAME} creation is successfull" | Out-File -FilePath $log_filename -Append
    } else {
        Write-Host "Step 2/11 : Key ${CONSUMER_KEY_NAME} creation is failed"
        "Step 2/11 : Key ${CONSUMER_KEY_NAME} creation is failed" | Out-File -FilePath $log_filename -Append

    }
}

if (IsGcloudSecretExists $RSA_PRIVATE_KEY_NAME) {
    Write-Host "Step 3/11 : Key ${RSA_PRIVATE_KEY_NAME} already exists, skipping the creation"
    "Step 3/11 : Key ${RSA_PRIVATE_KEY_NAME} already exists, skipping the creation" | Out-File -FilePath $log_filename -Append
} else {
    gcloud secrets create $RSA_PRIVATE_KEY_NAME --data-file=$PEM_FILE_PATH

    # Check if the secret creation was successful
    if ($LastExitCode -eq 0) {
        Write-Host "Step 3/11 : Key ${RSA_PRIVATE_KEY_NAME} creation is successfull"
        "Step 3/11 : Key ${RSA_PRIVATE_KEY_NAME} creation is successfull" | Out-File -FilePath $log_filename -Append
    } else {
        Write-Host "Step 3/11 : Key ${RSA_PRIVATE_KEY_NAME} creation is failed"
        "Step 3/11 : Key ${RSA_PRIVATE_KEY_NAME} creation is failed" | Out-File -FilePath $log_filename -Append
    }
}

$PROJECT_NUMBER = gcloud projects describe $PROJECT_ID --format="value(projectNumber)" 2>&1

function CreateGcsBucketIfNeeded {
    param (
        [string] $BucketName,
        [int] $stepNo
    )

    # Check if the bucket already exists
    $bucketExists = gcloud storage buckets list --filter="name=$BucketName" --format="value(name)" 2>&1

    if (-not $bucketExists) {
        # Create the bucket if it doesn't exist
        gcloud storage buckets create gs://$BucketName --project=$PROJECT_ID --location $LOCATION --uniform-bucket-level-access 2>&1

        if ($LastExitCode -eq 0) {
            Write-Host "Step ${stepNo}/11: Bucket '$BucketName' created successfully"
            "Step ${stepNo}/11 : Bucket '$BucketName' created successfully" | Out-File -FilePath $log_filename -Append
        } else {
            Write-Host "Step ${stepNo}/11: Error creating bucket"
            "Step ${stepNo}/11 : Error creating bucket" | Out-File -FilePath $log_filename -Append
        }
    } else {
        Write-Host "Step ${stepNo}/11 : Bucket with name '$BucketName' already exists, skipping its creation"
        "Step ${stepNo}/11 : Bucket with name '$BucketName' already exists, skipping its creation" | Out-File -FilePath $log_filename -Append
    }
}

CreateGcsBucketIfNeeded -BucketName $EVENT_GCS_BUCKET_SOURCE -stepNo 4
CreateGcsBucketIfNeeded -BucketName $SOURCE_CODE_BUCKET_NAME -stepNo 5

#upload the source code files
gcloud storage cp $SOURCE_CODE_LOCAL_PATH gs://$SOURCE_CODE_BUCKET_NAME

Write-Host "Step 6/11 : Successfully uploaded source code of cloud function from ${SOURCE_CODE_LOCAL_PATH} to bucket ${SOURCE_CODE_BUCKET_NAME}"

"Step 6/11 : Successfully uploaded source code of cloud function from ${SOURCE_CODE_LOCAL_PATH} to bucket ${SOURCE_CODE_BUCKET_NAME}" | Out-File -FilePath $log_filename -Append

# for below user needs to have permission secretmanager.secrets.setIamPolicy on the keys added above in SecretManager)
gcloud secrets add-iam-policy-binding $CONSUMER_KEY_NAME --role roles/secretmanager.secretAccessor --member serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com

Write-Host "Step 7/11 : Added iam-policy to ${CONSUMER_KEY_NAME} on ${PROJECT_NUMBER}"
"Step 7/11 : Added iam-policy to ${CONSUMER_KEY_NAME} on ${PROJECT_NUMBER}" | Out-File -FilePath $log_filename -Append

gcloud secrets add-iam-policy-binding $RSA_PRIVATE_KEY_NAME --role roles/secretmanager.secretAccessor --member serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com  >> $log_filename

Write-Host "Step 8/11 : Added iam-policy to ${RSA_PRIVATE_KEY_NAME} on ${PROJECT_NUMBER}"
"Step 8/11 : Added iam-policy to ${RSA_PRIVATE_KEY_NAME} on ${PROJECT_NUMBER}" | Out-File -FilePath $log_filename -Append

$create_event_function_name="${EVENT_GCS_BUCKET_SOURCE}-create-event-function"
$trimmed_create_event_function_name = $create_event_function_name.Substring(0, [Math]::Min(63, $create_event_function_name.Length))

gcloud functions deploy ${trimmed_create_event_function_name} --gen2 --runtime=python311 --region=${GCS_REGION} --source gs://${SOURCE_CODE_BUCKET_NAME}/${FILE_NAME} --entry-point=gcs_ingestion --trigger-event-filters="type=google.cloud.storage.object.v1.finalized" --trigger-event-filters="bucket=${EVENT_GCS_BUCKET_SOURCE}" --trigger-location=${TRIGGER_REGION} --set-env-vars SF_USERNAME=${SF_USERNAME} --set-env-vars SF_LOGIN_URL=${SF_LOGIN_URL} --set-env-vars PROJECT_ID=${PROJECT_ID} --set-env-vars CONSUMER_KEY=${CONSUMER_KEY_NAME} --set-env-vars RSA_PRIVATE_KEY=${RSA_PRIVATE_KEY_NAME}

Write-Host "Step 9/11 : Successfully deployed ${trimmed_create_event_function_name}"
"Step 9/11 : Successfully deployed ${trimmed_create_event_function_name}" | Out-File -FilePath $log_filename -Append

$delete_event_function_name="${EVENT_GCS_BUCKET_SOURCE}-delete-event-function"
$trimmed_delete_event_function_name = $delete_event_function_name.Substring(0, [Math]::Min(63, $delete_event_function_name.Length))

gcloud functions deploy ${trimmed_delete_event_function_name} --gen2 --runtime=python311 --region=${GCS_REGION} --source gs://${SOURCE_CODE_BUCKET_NAME}/${FILE_NAME} --entry-point=gcs_ingestion --trigger-event-filters="type=google.cloud.storage.object.v1.deleted" --trigger-event-filters="bucket=${EVENT_GCS_BUCKET_SOURCE}" --trigger-location=${TRIGGER_REGION} --set-env-vars SF_USERNAME=$SF_USERNAME --set-env-vars SF_LOGIN_URL=$SF_LOGIN_URL --set-env-vars PROJECT_ID=$PROJECT_ID --set-env-vars CONSUMER_KEY=$CONSUMER_KEY_NAME --set-env-vars RSA_PRIVATE_KEY=$RSA_PRIVATE_KEY_NAME

Write-Host "Step 10/11 : Successfully deployed ${trimmed_delete_event_function_name}"
"Step 10/11 : Successfully deployed ${trimmed_delete_event_function_name}" | Out-File -FilePath $log_filename -Append

$archive_event_function_name="${EVENT_GCS_BUCKET_SOURCE}-archive-event-function"
$trimmed_archive_event_function_name = $archive_event_function_name.Substring(0, [Math]::Min(63, $archive_event_function_name.Length))

gcloud functions deploy ${trimmed_archive_event_function_name} --gen2 --runtime=python311 --region=${GCS_REGION} --source gs://${SOURCE_CODE_BUCKET_NAME}/${FILE_NAME} --entry-point=gcs_ingestion --trigger-event-filters="type=google.cloud.storage.object.v1.archived" --trigger-event-filters="bucket=${EVENT_GCS_BUCKET_SOURCE}" --trigger-location=${TRIGGER_REGION} --set-env-vars SF_USERNAME=$SF_USERNAME --set-env-vars SF_LOGIN_URL=$SF_LOGIN_URL --set-env-vars PROJECT_ID=$PROJECT_ID --set-env-vars CONSUMER_KEY=$CONSUMER_KEY_NAME --set-env-vars RSA_PRIVATE_KEY=$RSA_PRIVATE_KEY_NAME

Write-Host "Step 11/11 : Successfully deployed ${trimmed_archive_event_function_name}"
"Step 11/11 : Successfully deployed ${trimmed_archive_event_function_name}" | Out-File -FilePath $log_filename -Append

"GCS EVENT NOTIFICATION SUCCESSFUL - Below is the summary of important resources" | Out-File -FilePath $log_filename -Append
"EVENT GCS BUCKET SOURCE NAME : ${EVENT_GCS_BUCKET_SOURCE}" | Out-File -FilePath $log_filename -Append
"SOURCE CODE BUCKET PATH : ${SOURCE_CODE_BUCKET_NAME}" | Out-File -FilePath $log_filename -Append
"CONSUMER KEY NAME : ${CONSUMER_KEY_NAME}" | Out-File -FilePath $log_filename -Append
"RSA PRIVATE KEY NAME : ${RSA_PRIVATE_KEY_NAME}" | Out-File -FilePath $log_filename -Append
"GCS REGION : ${GCS_REGION}" | Out-File -FilePath $log_filename -Append
"BUCKET LOCATION : ${LOCATION}" | Out-File -FilePath $log_filename -Append
"TRIGGER REGION : ${TRIGGER_REGION}" | Out-File -FilePath $log_filename -Append
"Create cloud function name : ${trimmed_create_event_function_name}" | Out-File -FilePath $log_filename -Append
"Delete cloud function name : ${trimmed_delete_event_function_name}" | Out-File -FilePath $log_filename -Append
"Archive cloud function name : ${trimmed_archive_event_function_name}" | Out-File -FilePath $log_filename -Append
"As a next step, you can create the relevant parent and second level directories (if they don't exist) in the above ${EVENT_GCS_BUCKET_SOURCE} bucket such that they align with the parent directory in GCS connector and the directory mentioned while UDLO creation" | Out-File -FilePath $log_filename -Append

Write-Host "All the gcs cloud function installer logs are logged to ${log_filename} file"

Write-Host "GCS EVENT NOTIFICATION SUCCESSFUL - Below is the summary of important resources"
Write-Host "EVENT GCS BUCKET SOURCE NAME : ${EVENT_GCS_BUCKET_SOURCE}"
Write-Host "SOURCE CODE BUCKET PATH : ${SOURCE_CODE_BUCKET_NAME}"
Write-Host "CONSUMER KEY NAME : ${CONSUMER_KEY_NAME}"
Write-Host "RSA PRIVATE KEY NAME : ${RSA_PRIVATE_KEY_NAME}"
Write-Host "GCS REGION : ${GCS_REGION}"
Write-Host "BUCKET LOCATION : ${LOCATION}"
Write-Host "TRIGGER REGION : ${TRIGGER_REGION}"
Write-Host "Create cloud function name : ${trimmed_create_event_function_name}"
Write-Host "Delete cloud function name : ${trimmed_delete_event_function_name}"
Write-Host "Archive cloud function name : ${trimmed_archive_event_function_name}"
Write-Host "As a next step, you can create the relevant parent and second level directories (if they don't exist) in the above ${EVENT_GCS_BUCKET_SOURCE} bucket such that they align with the parent directory in GCS connector and the directory mentioned while UDLO creation"