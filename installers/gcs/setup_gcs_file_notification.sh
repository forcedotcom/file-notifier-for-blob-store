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

#prerequisties - https://salesforce.quip.com/UGpYA1AUjb0e
#on running this script, the window will be redirected to gcs portal, just login and close the window, the script will continue its execution to completion
#run "chomod +x setup_gcs_file_notification.sh"
#run this file with command "./setup_gcs_file_notification.sh <input_parameters_gcs.conf>"
#make sure you have secrete manager access
#!/usr/bin/env bash
set -e

while true; do
  echo "Have you created connected app? (yes/no):"
  read user_input

  if [ "$user_input" == "yes" ]; then
    break
  elif [ "$user_input" == "no" ]; then
    echo "Please create connected app before running this script"
    exit
  else
    echo "Invalid input. Please enter 'yes' or 'no'."
  fi
done

while true; do
  echo "Have you downloaded the source code for cloud function from https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/cloud_function_zips/gcp_cloud_function.zip into your local machine? (yes/no):"
  read user_input

  if [ "$user_input" == "yes" ]; then
    break
  elif [ "$user_input" == "no" ]; then
    echo "Please download source code zip from https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/cloud_function_zips/gcp_cloud_function.zip"
    exit
  else
    echo "Invalid input. Please enter 'yes' or 'no'."
  fi
done

while true; do
  echo "As a pre-requiste you should have secretmanager access to your GCS project, do you have? (yes/no) : "
  read user_input

  if [ "$user_input" == "yes" ]; then
    break
  elif [ "$user_input" == "no" ]; then
    echo "IMPORTANT NOTE : As a pre-requiste you should have secretmanager access to your GCS project, please get the secretmanager access and then try again"
    exit
  else
    echo "Invalid input. Please enter 'yes' or 'no'."
  fi
done

while true; do
  echo "Running this script will create new GCS bucket (if it does not exists) and set up file event notifications on it. Agree to proceed? (yes/no):"
  read user_input

  if [ "$user_input" == "yes" ]; then
    break
  elif [ "$user_input" == "no" ]; then
    echo "Thank you"
    exit
  else
    echo "Invalid input. Please enter 'yes' or 'no'."
  fi
done

function install_gcloud_cli {
  #Check the operating system and perform actions accordingly
  if [[ "$OSTYPE" = "linux-gnu"* ]]; then
    echo "Choose the distribution of Linux : ubuntu/RedHat/Fedora? :"
    read linux_distribution_type

    if [ "$linux_distribution_type" == "ubuntu" ]; then
      sudo apt-get update
      sudo apt-get install apt-transport-https ca-certificates gnupg curl sudo
      curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
      echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
      sudo apt-get update && sudo apt-get install google-cloud-cli

    elif [ "$linux_distribution_type" == "RedHat" ]; then
      sudo dnf install google-cloud-cli

    elif [ "$linux_distribution_type" == "Fedora" ]; then
        sudo dnf install libxcrypt-compat.x86_64
        sudo dnf install google-cloud-cli

    else
      curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-466.0.0-linux-x86_64.tar.gz
      tar -xf google-cloud-cli-466.0.0-linux-x86_64.tar.gz
      ./google-cloud-sdk/install.sh
      ./google-cloud-sdk/bin/gcloud init

      if command -v gcloud &> /dev/null; then
        echo "gcloud CLI has been successfully installed."
      else
        echo "Invalid input, currently we support only ubuntu, RedHat, Fedora distributions of linux only"
        exit
      fi
    fi

  elif [ "$OSTYPE" = "darwin"* ]; then
    curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/google-cloud-sdk.zip
    unzip google-cloud-sdk.zip
    sudo ./google-cloud-sdk/install.sh
    gcloud init

  elif [ "$OSTYPE" = "cygwin*" | "$OSTYPE" = "mysys"* ]; then
    echo "Download the installer from https://cloud.google.com/sdk/docs/install#windows and follow the installation instructions."
    echo "After the installation, you may need to restart your terminal or command prompt to make the gcloud command available."
    echo "Verfiy the installation by running gcloud --version"
    exit;
  fi

  if command -v gcloud &> /dev/null; then
    echo "gcloud CLI has been successfully installed."
  else
    echo "Error: gcloud CLI installation failed, please install gcloud cli installation from https://cloud.google.com/sdk/docs/install and then re-run this script post installation"
  fi
}

current_time=$(date +"%Y-%m-%d_%H:%M:%S")
log_filename="log_${current_time}.txt"

echo "All the gcs cloud function installer logs are logged to ${log_filename} file"

if command -v gcloud &> /dev/null; then
  echo "gcloud CLI is already installed, skipping the installation"
  echo "gcloud CLI is already installed, skipping the installation" >> $log_filename
else
  install_gcloud_cli
fi

# Check if the config file is provided
if [[ -z "$1" ]]; then
  echo "Usage: $0 <config_file>"
  exit
fi

config_file=$1

# Check if the file exists
if [[ ! -f "$config_file" ]]; then
  echo "Error: File not found - $config_file"
  echo "Error: File not found - $config_file" >> $log_filename
  exit
fi

source $config_file

# Array to store validation errors
validation_errors=()

# Function to add an error to the array
add_validation_error() {
  validation_errors+=("$1")
}

function is_valid_region {
  #validation for valid compute region
  if gcloud compute regions list | grep -q $GCS_REGION ; then
    echo "${GCS_REGION} is a valid region"
    echo "${GCS_REGION} is a valid region" >> $log_filename
  else
    add_validation_error "Region ${GCS_REGION} region is invalid, please use a valid region and run 'gcloud compute regions list' to get list of valid regions";
  fi
}

#validation for valid bucket location
function is_valid_location {
  if gcloud compute regions list | grep -q $LOCATION ; then
    echo "${LOCATION} is a valid location"
    echo "${LOCATION} is a valid location" >> $log_filename
  else
    add_validation_error "Bucket location ${LOCATION} is invalid, please use a valid bucket location and run 'gcloud compute regions list' to get list of valid bucket locations";
  fi
}

function is_valid_gcs_bucket_name {
    local gcs_bucket_name="$1"
    local regex="^[a-z0-9][a-z0-9_-]*[a-z0-9]$"

    if [ -z "$gcs_bucket_name" ]; then
      add_validation_error "Error: gcs bucket is missing/empty. Please provide a valid gcs bucket name"
    elif [[ "$gcs_bucket_name" =~ $regex ]]; then
      echo "$gcs_bucket_name is a valid bucket name"
      echo "$gcs_bucket_name is a valid bucket name" >> $log_filename
    else
      add_validation_error "Error: Invalid GCS Bucket Name: ${gcs_bucket_name}"
    fi
}

#validate the existance of local source code path for cloud function
function is_valid_source_code_local_path {
  if [ -z "$SOURCE_CODE_LOCAL_PATH" ]; then
    add_validation_error "Error: Source code local path is missing/empty. Please provide a valid Source code local path and source code zip can be downloaded from https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/cloud_function_zips/gcp_cloud_function.zip"
  elif [ -f $SOURCE_CODE_LOCAL_PATH ]; then
    echo "Source code for cloud function exists at ${SOURCE_CODE_LOCAL_PATH}"
    echo "Source code for cloud function exists at ${SOURCE_CODE_LOCAL_PATH}" >> $log_filename

    local filename=$(basename "$SOURCE_CODE_LOCAL_PATH")

    if [[ "$filename" == *.zip ]]; then
      echo "${SOURCE_CODE_LOCAL_PATH} has a valid file of type .zip"
      echo "${SOURCE_CODE_LOCAL_PATH} has a valid file of type .zip" >> $log_filename
    else
      add_validation_error "Error: Please include file with .zip extension for SOURCE_CODE_LOCAL_PATH"
    fi

  else
    add_validation_error "Error: Source code local path ${SOURCE_CODE_LOCAL_PATH} for cloud function deployment does not exist or is invalid, please validate your input config, source code zip can be downloaded from https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/cloud_function_zips/gcp_cloud_function.zip"
  fi
}

function is_valid_pem_file_path {
  #validate the existance of local pem file path for adding secrete keys
  if [ -z "$PEM_FILE_PATH" ]; then
    add_validation_error "Error: PEM_FILE_PATH or keypair.pem file path is missing/empty. Please provide a valid .pem file path"
  elif [ -f $PEM_FILE_PATH ]; then
    echo "pem file exists at ${PEM_FILE_PATH}"
    echo "pem file exists at ${PEM_FILE_PATH}" >> $log_filename
  else
    add_validation_error "Error: PEM_FILE_PATH - ${PEM_FILE_PATH} for creating RSA_PRIVATE_KEY does not exist or is invalid or is not of .pem type, please create it using openssl commands"
  fi

  # Extract file name without path and check if the file name ends with ".pem"
  local filename=$(basename "$PEM_FILE_PATH")

  if [[ "$filename" == *.pem ]]; then
    echo "$filename is a valid .pem file"
    echo "$filename is a valid .pem file" >> $log_filename
  else
    add_validation_error "Error: Please include file with .pem extension for PEM_FILE_PATH"
  fi
}

function is_valid_consumer_key_name {
    local pattern="^CONSUMER_KEY_[a-zA-Z0-9_-]+$"

    if [[ $CONSUMER_KEY_NAME =~ $pattern ]]; then
        echo "${CONSUMER_KEY_NAME} is a valid consumer key name"
        echo "${CONSUMER_KEY_NAME} is a valid consumer key name" >> $log_filename
    else
        add_validation_error "Error: The consumer key with name ${CONSUMER_KEY_NAME} does not match the pattern CONSUMER_KEY_<Your own suffix>."
    fi
}

function is_valid_rsa_private_key_name {
    local pattern="^RSA_PRIVATE_KEY_[a-zA-Z0-9_-]+$"

    if [[ $RSA_PRIVATE_KEY_NAME =~ $pattern ]]; then
      echo "${RSA_PRIVATE_KEY_NAME} is a valid rsa private key"
      echo "${RSA_PRIVATE_KEY_NAME} is a valid rsa private key" >> $log_filename
    else
      add_validation_error "Error: The rsa private key with name ${RSA_PRIVATE_KEY_NAME} does not match the pattern RSA_PRIVATE_KEY_<Your own suffix>."
    fi
}

is_valid_region
is_valid_location
is_valid_gcs_bucket_name $EVENT_GCS_BUCKET_SOURCE
is_valid_gcs_bucket_name $SOURCE_CODE_BUCKET_NAME
is_valid_source_code_local_path
is_valid_pem_file_path
is_valid_consumer_key_name
is_valid_rsa_private_key_name

# Print all the validation errors
if [ ${#validation_errors[@]} -gt 0 ]; then
  echo "There are validation errors as below:"
  echo "There are validation errors as below:" >> $log_filename
  for validation_error in "${validation_errors[@]}"; do
    echo "$validation_error"
    echo "$validation_error" >> $log_filename
  done
  echo "NOTE: Please check descriptions of each variable in https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/installers/gcs/input_parameters_gcs.conf"
  echo "NOTE: Please check descriptions of each variable in https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/installers/gcs/input_parameters_gcs.conf" >> $log_filename
  exit
else
  echo "No validation errors."
  echo "No validation errors." >> $log_filename
fi

FILE_NAME=$(basename "$SOURCE_CODE_LOCAL_PATH")

gcloud auth login >> $log_filename

echo "Step 1/11 : Successfully logged into GCS"
echo "Step 1/11 : Successfully logged into GCS" >> $log_filename

if gcloud projects describe $PROJECT_ID 2>&1 | grep -q "it may not exist" ; then
  echo "${PROJECT_ID} does not exists or you may not have permissions to it, please use right project or create a new project";
  exit;
fi

gcloud config set project $PROJECT_ID

gcloud services enable pubsub.googleapis.com
gcloud services enable secretmanager.googleapis.com

#validation for valid consumer key and creation
if gcloud secrets describe $CONSUMER_KEY_NAME --project=$PROJECT_ID 2>&1 | grep -q "NOT_FOUND" ; then

  CONSUMER_KEY_FILE="consumer_key.txt"
  echo "$CONSUMER_KEY_VALUE" > "$CONSUMER_KEY_FILE"
  gcloud secrets create $CONSUMER_KEY_NAME --data-file=${CONSUMER_KEY_FILE}

  if [ $? -eq 0 ]; then
    echo "Step 2/11 : Key ${CONSUMER_KEY_NAME} creation is successfull";
    echo "Step 2/11 : Key ${CONSUMER_KEY_NAME} creation is successfull" >> $log_filename
  else
    echo "Step 2/11 : Key ${CONSUMER_KEY_NAME} creation is failed";
    echo "Step 2/11 : Key ${CONSUMER_KEY_NAME} creation is failed" >> $log_filename
  fi

else
 echo "Step 2/11 : Key ${CONSUMER_KEY_NAME} already exists, skipping the creation"
 echo "Step 2/11 : Key ${CONSUMER_KEY_NAME} already exists, skipping the creation" >> $log_filename
fi

#validation for valid secrete key and creation
if gcloud secrets describe $RSA_PRIVATE_KEY_NAME --project=$PROJECT_ID 2>&1 | grep -q "NOT_FOUND" ; then
   gcloud secrets create ${RSA_PRIVATE_KEY_NAME} --data-file ${PEM_FILE_PATH} >> $log_filename

   if [ $? -eq 0 ]; then
     echo "Step 3/11 : Key ${RSA_PRIVATE_KEY_NAME} creation is successfull";
     echo "Step 3/11 : Key ${RSA_PRIVATE_KEY_NAME} creation is successfull" >> $log_filename
   else
     echo "Step 3/11 : Key ${RSA_PRIVATE_KEY_NAME} creation is failed";
     echo "Step 3/11 : Key ${RSA_PRIVATE_KEY_NAME} creation is failed" >> $log_filename
   fi

else
 echo "Step 3/11 : Key ${RSA_PRIVATE_KEY_NAME} already exists, skipping the creation"
 echo "Step 3/11 : Key ${RSA_PRIVATE_KEY_NAME} already exists, skipping the creation" >> $log_filename
fi

PROJECT_NUMBER=$(gcloud projects list --filter="project_id:$PROJECT_ID" --format='value(project_number)')

#create if only if it does not exists
if gcloud storage buckets list --project=$PROJECT_ID --filter=name="${EVENT_GCS_BUCKET_SOURCE}" --format="value(name)" | grep -qx ${EVENT_GCS_BUCKET_SOURCE} ; then
   echo "Step 4/11 : Bucket with name ${EVENT_GCS_BUCKET_SOURCE} exists and skipping the creation of gcs bucket";
   echo "Step 4/11 : Bucket with name ${EVENT_GCS_BUCKET_SOURCE} exists and skipping the creation of gcs bucket" >> $log_filename
else
  gcloud storage buckets create gs://$EVENT_GCS_BUCKET_SOURCE --project=$PROJECT_ID --location $LOCATION  >> $log_filename


  if [ $? -eq 0 ]; then
    echo "Step 4/11 : Successfully created bucket ${EVENT_GCS_BUCKET_SOURCE}"
    echo "Step 4/11 : Successfully created bucket ${EVENT_GCS_BUCKET_SOURCE}" >> $log_filename
  else
    echo "Step 4/11 : Failed to create bucket ${EVENT_GCS_BUCKET_SOURCE}"
    echo "Step 4/11 : Failed to create bucket ${EVENT_GCS_BUCKET_SOURCE}" >> $log_filename
  fi

fi

#create if only if it does not exists
if gcloud storage buckets list --project=$PROJECT_ID --filter=name="${SOURCE_CODE_BUCKET_NAME}" --format="value(name)" | grep -qx ${SOURCE_CODE_BUCKET_NAME} ; then
  echo "Step 5/11 : Bucket with name ${SOURCE_CODE_BUCKET_NAME} exists and skipping the creation of gcs bucket";
  echo "Step 5/11 : Bucket with name ${SOURCE_CODE_BUCKET_NAME} exists and skipping the creation of gcs bucket" >> $log_filename
else
  gcloud storage buckets create gs://$SOURCE_CODE_BUCKET_NAME --project=$PROJECT_ID --location $LOCATION --uniform-bucket-level-access  >> $log_filename

  if [ $? -eq 0 ]; then
    echo "Step 5/11 : Successfully created bucket ${SOURCE_CODE_BUCKET_NAME}"
    echo "Step 5/11 : Successfully created bucket ${SOURCE_CODE_BUCKET_NAME}" >> $log_filename
  else
    echo "Step 5/11 : Failed to create bucket ${SOURCE_CODE_BUCKET_NAME}"
    echo "Step 5/11 : Failed to create bucket ${SOURCE_CODE_BUCKET_NAME}" >> $log_filename
  fi

fi

#upload the source code files
gcloud storage cp $SOURCE_CODE_LOCAL_PATH gs://$SOURCE_CODE_BUCKET_NAME

echo "Step 6/11 : Successfully uploaded source code of cloud function from ${SOURCE_CODE_LOCAL_PATH} to bucket ${SOURCE_CODE_BUCKET_NAME}"
echo "Step 6/11 : Successfully uploaded source code of cloud function from ${SOURCE_CODE_LOCAL_PATH} to bucket ${SOURCE_CODE_BUCKET_NAME}" >> $log_filename

# for below user needs to have permission secretmanager.secrets.setIamPolicy on the keys added above in SecretManager)
gcloud secrets add-iam-policy-binding $CONSUMER_KEY_NAME \
  --role roles/secretmanager.secretAccessor \
  --member serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com  >> $log_filename

echo "Step 7/11 : Added iam-policy to ${CONSUMER_KEY_NAME} on ${PROJECT_NUMBER}"
echo "Step 7/11 : Added iam-policy to ${CONSUMER_KEY_NAME} on ${PROJECT_NUMBER}" >> $log_filename

gcloud secrets add-iam-policy-binding $RSA_PRIVATE_KEY_NAME \
  --role roles/secretmanager.secretAccessor \
  --member serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com  >> $log_filename

echo "Step 8/11 : Added iam-policy to ${RSA_PRIVATE_KEY_NAME} on ${PROJECT_NUMBER}"
echo "Step 8/11 : Added iam-policy to ${RSA_PRIVATE_KEY_NAME} on ${PROJECT_NUMBER}" >> $log_filename

create_event_function_name="${EVENT_GCS_BUCKET_SOURCE}-create-event-function"
trimmed_create_event_function_name="${create_event_function_name:0:63}"

gcloud functions deploy $trimmed_create_event_function_name \
--gen2 \
--runtime=python311 \
--region=$GCS_REGION \
--source=gs://$SOURCE_CODE_BUCKET_NAME/$FILE_NAME \
--entry-point=gcs_ingestion \
--trigger-event-filters="type=google.cloud.storage.object.v1.finalized" \
--trigger-event-filters="bucket=${EVENT_GCS_BUCKET_SOURCE}" \
--trigger-location=$TRIGGER_REGION \
--set-env-vars SF_USERNAME=$SF_USERNAME,SF_LOGIN_URL=$SF_LOGIN_URL,PROJECT_ID=$PROJECT_ID,CONSUMER_KEY=$CONSUMER_KEY_NAME,RSA_PRIVATE_KEY=$RSA_PRIVATE_KEY_NAME >> $log_filename

echo "Step 9/11 : Successfully deployed ${trimmed_create_event_function_name}"
echo "Step 9/11 : Successfully deployed ${trimmed_create_event_function_name}" >> $log_filename

delete_event_function_name="${EVENT_GCS_BUCKET_SOURCE}-delete-event-function"
trimmed_delete_event_function_name="${delete_event_function_name:0:63}"

gcloud functions deploy $trimmed_delete_event_function_name \
--gen2 \
--runtime=python311 \
--region=$GCS_REGION \
--source=gs://$SOURCE_CODE_BUCKET_NAME/$FILE_NAME \
--entry-point=gcs_ingestion \
--trigger-event-filters="type=google.cloud.storage.object.v1.deleted" \
--trigger-event-filters="bucket=${EVENT_GCS_BUCKET_SOURCE}" \
--trigger-location=$TRIGGER_REGION \
--set-env-vars SF_USERNAME=$SF_USERNAME,SF_LOGIN_URL=$SF_LOGIN_URL,SF_AUDIENCE_URL=$SF_AUDIENCE_URL,PROJECT_ID=$PROJECT_ID,CONSUMER_KEY=$CONSUMER_KEY_NAME,RSA_PRIVATE_KEY=$RSA_PRIVATE_KEY_NAME >> $log_filename

echo "Step 10/11 : Successfully deployed ${trimmed_delete_event_function_name}"
echo "Step 10/11 : Successfully deployed ${trimmed_delete_event_function_name}" >> $log_filename

archive_event_function_name="${EVENT_GCS_BUCKET_SOURCE}-archive-event-function"
trimmed_archive_event_function_name="${archive_event_function_name:0:63}"

gcloud functions deploy $trimmed_archive_event_function_name \
--gen2 \
--runtime=python311 \
--region=$GCS_REGION \
--source=gs://$SOURCE_CODE_BUCKET_NAME/$FILE_NAME \
--entry-point=gcs_ingestion \
--trigger-event-filters="type=google.cloud.storage.object.v1.archived" \
--trigger-event-filters="bucket=${EVENT_GCS_BUCKET_SOURCE}" \
--trigger-location=$TRIGGER_REGION \
--set-env-vars SF_USERNAME=$SF_USERNAME,SF_LOGIN_URL=$SF_LOGIN_URL,PROJECT_ID=$PROJECT_ID,CONSUMER_KEY=$CONSUMER_KEY_NAME,RSA_PRIVATE_KEY=$RSA_PRIVATE_KEY_NAME >> $log_filename

echo "Step 11/11 : Successfully deployed ${trimmed_archive_event_function_name}"
echo "Step 11/11 : Successfully deployed ${trimmed_archive_event_function_name}" >> $log_filename
echo "All the gcs cloud function installer logs are logged to ${log_filename} file"

echo "GCS EVENT NOTIFICATION SUCCESSFUL - Below is the summary of important resources"
echo "EVENT GCS BUCKET SOURCE NAME : ${EVENT_GCS_BUCKET_SOURCE}"
echo "SOURCE CODE BUCKET PATH : ${SOURCE_CODE_BUCKET_NAME}"
echo "CONSUMER KEY NAME : ${CONSUMER_KEY_NAME}"
echo "RSA PRIVATE KEY NAME : ${RSA_PRIVATE_KEY_NAME}"
echo "GCS REGION : ${GCS_REGION}"
echo "BUCKET LOCATION : ${LOCATION}"
echo "TRIGGER REGION : ${TRIGGER_REGION}"
echo "Create cloud function name : ${trimmed_create_event_function_name}"
echo "Delete cloud function name : ${trimmed_delete_event_function_name}"
echo "Archive cloud function name : ${trimmed_archive_event_function_name}"
echo "As a next step, you can create the relevant parent and second level directories (if they don't exist) in the above ${EVENT_GCS_BUCKET_SOURCE} bucket such that they align with the parent directory in GCS connector and the directory mentioned while UDLO creation"