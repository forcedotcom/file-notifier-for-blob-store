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
#export JIT credentials into terminal before running it or perform run 'aws configure' in your terminal
#run "chmod +x setup_s3_file_notification.sh"
#run this file with command "./setup_s3_file_notification.sh input_parameters_s3.conf"
#make sure you have the credentials of the aws admin role
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
  echo "Have you added/configured aws credentials of admin role to terminal, It is a must to have admin role credentials? (yes/no):"
  read user_input

  if [ "$user_input" == "yes" ]; then
    break
  elif [ "$user_input" == "no" ]; then
    echo "Please add/configure aws credentials of admin role in terminal before running this script or add below policy to your iam user which has access to your bucket"
    echo '
          {
            "Version": "2012-10-17",
            "Statement": [
            {
              "Effect": "Allow",
              "Action": [
                "iam:CreateRole",
                "iam:GetRole",
                "lambda:CreateFunction",
                "lambda:GetFunction",
                "lambda:InvokeFunction",
                "iam:AttachRolePolicy",
                "secretsmanager:PutResourcePolicy",
                "secretsmanager:CreateSecret"
              ],
              "Resource": "*"
            },
            {
              "Effect": "Allow",
              "Action": [
                "iam:PassRole"
              ],
              "Resource": "arn:aws:iam::<YOUR_AWS_ACCOUNT_ID>:role/<YOUR_LAMBDA_ROLE>"
            }
          ]
        }'
    exit
  else
    echo "Invalid input. Please enter 'yes' or 'no'."
  fi
done

while true; do
  echo "Have you downloaded the source code for cloud function from https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/cloud_function_zips/aws_lambda_function.zip into your local machine? (yes/no):"
  read user_input

  if [ "$user_input" == "yes" ]; then
    break
  elif [ "$user_input" == "no" ]; then
    echo "Please download source code zip from https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/cloud_function_zips/aws_lambda_function.zip"
    exit
  else
    echo "Invalid input. Please enter 'yes' or 'no'."
  fi
done

while true; do
  echo "Running this script will create new s3 bucket and the folder/s3 key (if it does not exists) and setup file event notification on it. Agree to proceed? (yes/no):"
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

function install_aws_cli {
  #Check the operating system and perform actions accordingly
  if [[ "$OSTYPE" = "linux-gnu"* ]]; then
    curl "https://d1vvhvl2y92vvt.cloudfront.net/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip awscliv2.zip
    sudo ./aws/install

    #install jq
    sudo apt-get update
    sudo apt-get install jq

  elif [[ "$OSTYPE" = "darwin"* ]]; then
    brew install awscli

    #install jq
    brew install jq

  elif [[ "$OSTYPE" = "cygwin*" || "$OSTYPE" = "msys"* ]]; then
    echo "Download and run the AWS CLI MSI installer for Windows (64-bit): https://awscli.amazonaws.com/AWSCLIV2.msi"
    echo "Install jq from https://jqlang.github.io/jq/download/"
    echo "Download and run the AWS CLI MSI installer for Windows (64-bit): https://awscli.amazonaws.com/AWSCLIV2.msi" >> $log_filename
    echo "Install jq from https://jqlang.github.io/jq/download/" >> $log_filename
    exit;
  fi

  if command -v aws &> /dev/null; then
    echo "AWS CLI has been successfully installed."
    echo "AWS CLI has been successfully installed." >> $log_filename
  else
    echo "Error: AWS CLI installation failed."
    echo "Error: AWS CLI installation failed." >> $log_filename
  fi
}

# Check if the config file is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <config_file>"
  exit 1
fi

config_file=$1

# Check if the file exists
if [ ! -f "$config_file" ]; then
  echo "Error: File not found - $config_file"
  echo "Error: File not found - $config_file" >> $log_filename
  exit 1
fi

source $config_file

current_time=$(date +"%Y-%m-%d_%H:%M:%S")

log_filename="log_${current_time}.txt"

echo "All the s3 cloud function installer logs are logged to ${log_filename} file"

if command -v aws &> /dev/null; then
  echo "aws CLI is already installed, skipping the installation"
  echo "aws CLI is already installed, skipping the installation" >> $log_filename
else
  install_aws_cli
fi

# Array to store validation errors
validation_errors=()

# Function to add an error to the array
add_validation_error() {
  validation_errors+=("$1")
}

# Check if AWS keys is set
function is_aws_credentials_configured {
  if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ] || [ -z "$AWS_SESSION_TOKEN" ]; then
    echo "Please export all the three AWS credentials (AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN) and paste it to terminal (please use https://docs.aws.amazon.com/keyspaces/latest/devguide/access.credentials.html to generate it)"
    echo "Please export all the three AWS credentials (AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN) and paste it to terminal (please use https://docs.aws.amazon.com/keyspaces/latest/devguide/access.credentials.html to generate it)" >> $log_filename
    exit
  else
    echo "AWS credentials are exported correctly"
    echo "AWS credentials are exported correctly" >> $log_filename
  fi
}

#validate if security tokens are valid
function is_aws_credentials_valid {
  if aws sts get-caller-identity | grep -q "Arn" ; then
    echo "AWS credentials entered in terminal are valid"
    echo "AWS credentials entered in terminal are valid" >> $log_filename
  else
    echo "Error: Security credentials/tokens are either expired or invalid and please use valid security tokens";
    echo "Error: Security credentials/tokens are either expired or invalid and please use valid security tokens" >> $log_filename
    exit
fi
}

#validation for valid region
function is_valid_region {
  if echo "$(aws ec2 describe-regions --query 'Regions[*].[RegionName]' --output text)" | grep -q $REGION ; then
    echo "${REGION} is a valid region"
    echo "${REGION} is a valid region" >> $log_filename
  else
    add_validation_error "${REGION} region is invalid, please use a valid region";
  fi
}

#validate for valid bucket name
function is_valid_s3_bucket_name {
    local s3_bucket_name="$1"
    local regex="^[a-z0-9.-]*$"

    if [ -z "$s3_bucket_name" ]; then
      add_validation_error "Error: s3 bucket name is missing/empty. Please provide a valid s3 bucket name"
    elif [[ $s3_bucket_name =~ $regex ]] && [[ ${#s3_bucket_name} -ge 3 ]] && [[ ${#s3_bucket_name} -le 63 ]]; then
      echo "${s3_bucket_name} is a valid bucket name"
      echo "${s3_bucket_name} is a valid bucket name" >> $log_filename
    else
      add_validation_error "Error: Invalid AWS S3 bucket name: ${s3_bucket_name}, Only lowercase alphanumeric characters, hyphens, and dots are allowed"
    fi
}

#validate for valid iam role name
function is_valid_lambda_role_name {
    local regex="^[a-zA-Z0-9_+=,.@-]*$"

    if [ -z "$LAMBDA_ROLE" ]; then
      add_validation_error "Error: LAMBDA_ROLE or IAM role name is missing/empty. Please provide a valid IAM role name"
    fi

    if [[ ! $LAMBDA_ROLE =~ $regex ]]; then
      add_validation_error "Error: Invalid LAMBDA_ROLE or IAM role name: ${LAMBDA_ROLE}. Only alphanumeric characters, hyphens, underscores, commas, periods, at signs (@), and the plus sign (+) are allowed."
    fi

    if [[ ${#LAMBDA_ROLE} -lt 1 || ${#iam_role_name} -gt 128 ]]; then
      add_validation_error "Error: Invalid LAMBDA_ROLE or IAM role name: ${LAMBDA_ROLE}. Length must be between 1 and 128 characters."
    fi
}

#validate for valid secrete key name
function is_valid_aws_secret_key_name {
    local aws_secret_key_name="$1"
    local regex="^[A-Za-z0-9/_+=-]+$"

    if [[ ! $aws_secret_key_name =~ $regex ]]; then
        add_validation_error "Invalid AWS secret key name - $aws_secret_key_name. Either CONSUMER_KEY or RSA_PRIVATE_KEY name is invaid, It may contain only alphanumeric characters and the characters /_+=-."
    fi
}

#validate the existance of local source code path for cloud function
function is_valid_source_code_local_path {
  if [ -z "$SOURCE_CODE_LOCAL_PATH" ]; then
    add_validation_error "Error: Source code local path is missing/empty. Please provide a valid Source code local path and source code zip can be downloaded from https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/cloud_function_zips/aws_lambda_function.zip"
  elif [ -f $SOURCE_CODE_LOCAL_PATH ]; then
    echo "local source code for cloud function exists at ${SOURCE_CODE_LOCAL_PATH}"
    echo "local source code for cloud function exists at ${SOURCE_CODE_LOCAL_PATH}" >> $log_filename

    local filename=$(basename "$SOURCE_CODE_LOCAL_PATH")

    if [[ "$filename" == *.zip ]]; then
      echo "${SOURCE_CODE_LOCAL_PATH} has a valid file of type .zip"
      echo "${SOURCE_CODE_LOCAL_PATH} has a valid file of type .zip" >> $log_filename
    else
      add_validation_error "Error: Please include file with .zip extension for SOURCE_CODE_LOCAL_PATH"
    fi

  else
    add_validation_error "Error: Source code local path ${SOURCE_CODE_LOCAL_PATH} for cloud function deployment does not exist or is invalid, please validate your input config, source code zip can be downloaded from  https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/cloud_function_zips/aws_lambda_function.zip"
fi
}

function is_valid_pem_file_path {
  #validate the existance of local pem file path for adding secrete keys
  if [ -z "$PEM_FILE_PATH" ]; then
    add_validation_error "Error: keypair.pem file path is missing/empty. Please provide a valid .pem file path"
  elif [ -f $PEM_FILE_PATH ]; then
    echo "PEM file required for creation of secrete exists at ${PEM_FILE_PATH}"
    echo "PEM file required for creation of secrete exists at ${PEM_FILE_PATH}" >> $log_filename
  else
    add_validation_error "Error: PEM_FILE_PATH - ${PEM_FILE_PATH} for creating RSA_PRIVATE_KEY does not exist or is invalid or is not of .pem type, please create it using openssl commands"
  fi

  # Extract file name without path and check if the file name ends with ".pem"
  local filename=$(basename "$PEM_FILE_PATH")

  if [[ "$filename" == *.pem ]]; then
    echo "${PEM_FILE_PATH} has a valid file of type .pem"
    echo "${PEM_FILE_PATH} has a valid file of type .pem" >> $log_filename
  else
    add_validation_error "Error: Please include file with .pem extension for PEM_FILE_PATH"
  fi
}

#validate name of lambda function
function is_valid_lambda_func_name {
    local lambda_func_name="$1"
    local regex="^[a-zA-Z0-9_-]+$"

    if [ -z "$lambda_func_name" ]; then
      add_validation_error "Error: LAMBDA_FUNC_NAME is missing/empty. Please provide a valid LAMBDA_FUNC_NAME"
    fi

    if [[ ! $lambda_func_name =~ $regex ]]; then
      add_validation_error "Invalid Lambda function name: $lambda_func_name. Only alphanumeric characters, hyphens, and underscores are allowed."
    fi

    if [[ ${#lambda_func_name} -lt 1 || ${#lambda_func_name} -gt 64 ]]; then
      add_validation_error "Invalid Lambda function name: $lambda_func_name. Length must be between 1 and 64 characters."
    fi
}

#validate name of the s3 folder in the bucket
function is_valid_folder_name_in_s3_bucket {
  local folder_name="$1"
  local bucket_name="$2"
  local regex="^[[:alnum:]].*[[:alnum:]]$"

  # Check if the string matches the regex
  if [[ $folder_name =~ $regex ]]; then
    echo "${folder_name} folder name with in ${bucket_name} bucket is valid which starts with an alphanumeric character and ends with an alphanumeric character."
  else
    add_validation_error "Error: ${folder_name} folder name with in ${bucket_name} bucket is invalid, folder name should start and end with alphanumeric characters"
  fi
}

is_aws_credentials_configured
is_aws_credentials_valid
is_valid_region
is_valid_s3_bucket_name $EVENT_S3_SOURCE_BUCKET
is_valid_s3_bucket_name $LAMBDA_FUNC_S3_BUCKET
is_valid_folder_name_in_s3_bucket $EVENT_S3_SOURCE_KEY $EVENT_S3_SOURCE_BUCKET
is_valid_folder_name_in_s3_bucket $LAMBDA_FUNC_LOC_S3_KEY $LAMBDA_FUNC_S3_BUCKET
is_valid_lambda_role_name
is_valid_aws_secret_key_name $CONSUMER_KEY_NAME
is_valid_aws_secret_key_name $RSA_PRIVATE_KEY_NAME
is_valid_source_code_local_path
is_valid_pem_file_path
is_valid_lambda_func_name $LAMBDA_FUNC_NAME

# Print all the validation errors
if [ ${#validation_errors[@]} -gt 0 ]; then
  echo "There are validation errors as below:"
  echo "There are validation errors as below:" >> $log_filename
  for validation_error in "${validation_errors[@]}"; do
    echo "$validation_error"
    echo "$validation_error" >> $log_filename
  done
  echo "NOTE: Please check sample config file at https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/installers/aws/input_parameters_s3.conf"
  echo "NOTE: Please check sample config file at https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/installers/aws/input_parameters_s3.conf" >> $log_filename
  exit
else
  echo "No validation errors."
  echo "No validation errors." >> $log_filename
fi

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "jq is not installed"
    echo "jq is not installed" >> $log_filename
fi

echo "Step 1/16 : Successfully logged into AWS"
echo "Step 1/16 : Successfully logged into AWS" >> $log_filename

aws configure set region $REGION
aws configure set output "json"

current_epoch_time=$(date +%s)

# Check if the IAM role exists
if aws iam get-role --role-name "$LAMBDA_ROLE" 2>&1 | grep -q "NoSuchEntity"; then

   # Create the IAM role
   aws iam create-role --role-name $LAMBDA_ROLE \
  --assume-role-policy-document \
  '{"Version": "2012-10-17","Statement": [{ "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}' >> $log_filename

    if [ $? -eq 0 ]; then
      echo "Step 2/16 : Successfully created iam-role with name ${LAMBDA_ROLE}.";
      echo "Step 2/16 : Successfully created iam-role with name ${LAMBDA_ROLE}." >> $log_filename
    else
      echo "Step 2/16 : Failed to create iam-role with name ${LAMBDA_ROLE}."
      echo "Step 2/16 : Failed to create iam-role with name ${LAMBDA_ROLE}." >> $log_filename
    fi

else
    echo "Step 2/16 : iam-role with name ${LAMBDA_ROLE} already exists, skipping creation"
    echo "Step 2/16 : iam-role with name ${LAMBDA_ROLE} already exists, skipping creation" >> $log_filename
fi

LAMBDA_ROLE_ARN=$(aws iam get-role --role-name $LAMBDA_ROLE \
--query 'Role.Arn' --output text)

echo "LAMBDA_ROLE_ARN: ${LAMBDA_ROLE_ARN}"
echo "LAMBDA_ROLE_ARN: ${LAMBDA_ROLE_ARN}" >> $log_filename

# Check if the consumer key secret exists
if aws secretsmanager get-secret-value --secret-id "$CONSUMER_KEY_NAME" 2>&1 | grep -q "ResourceNotFoundException"; then
    # Create the consumer key secret
   aws secretsmanager create-secret \
    --name $CONSUMER_KEY_NAME \
    --secret-string $CONSUMER_KEY_VALUE >> $log_filename

    if [ $? -eq 0 ]; then
      echo "Step 3/16 : Secrete Key with name $CONSUMER_KEY_NAME created successfully."
      echo "Step 3/16 : Secrete Key with name $CONSUMER_KEY_NAME created successfully." >> $log_filename
    else
      echo "Step 3/16 : Failed to create secrete Key with name $CONSUMER_KEY_NAME."
      echo "Step 3/16 : Failed to create secrete Key with name $CONSUMER_KEY_NAME." >> $log_filename
    fi

else
    echo "Step 3/16 : ${CONSUMER_KEY_NAME} already exists, skipping the creation"
    echo "Step 3/16 : ${CONSUMER_KEY_NAME} already exists, skipping the creation" >> $log_filename
fi

# Check if the rsa private key secret exists
if aws secretsmanager get-secret-value --secret-id "$RSA_PRIVATE_KEY_NAME" 2>&1 | grep -q "ResourceNotFoundException"; then
    # Create the consumer key secret
   aws secretsmanager create-secret \
    --name $RSA_PRIVATE_KEY_NAME \
    --secret-string "$(cat ${PEM_FILE_PATH})" >> $log_filename

  if [ $? -eq 0 ]; then
    echo "Step 4/16 : Successfully created ${RSA_PRIVATE_KEY_NAME}"
    echo "Step 4/16 : Successfully created ${RSA_PRIVATE_KEY_NAME}" >> $log_filename
  else
    echo "Step 4/16 : Failed to create secrete Key with name $RSA_PRIVATE_KEY_NAME."
    echo "Step 4/16 : Failed to create secrete Key with name $RSA_PRIVATE_KEY_NAME." >> $log_filename
  fi

else
    echo "Step 4/16 : ${RSA_PRIVATE_KEY_NAME} already exists, skipping the creation"
    echo "Step 4/16 : ${RSA_PRIVATE_KEY_NAME} already exists, skipping the creation" >> $log_filename
fi

# Get a list of all buckets
list_of_existing_aws_s3_buckets=$(aws s3api list-buckets --query 'Buckets[*].Name' --output text)

source_bucket_exists="false";
#check if the bucket exists
for item in $list_of_existing_aws_s3_buckets
do
    if [ "${LAMBDA_FUNC_S3_BUCKET}" == "${item}" ]; then
      source_bucket_exists="true";
    fi
done

if [ "$source_bucket_exists" == "true" ]; then
  echo "Step 5/16 : Bucket ${LAMBDA_FUNC_S3_BUCKET} exists, skipping the creation of new bucket"
  echo "Step 5/16 : Bucket ${LAMBDA_FUNC_S3_BUCKET} exists, skipping the creation of new bucket" >> $log_filename
else
  if [ "$REGION" == "us-east-1" ]; then
    aws s3api create-bucket --bucket $LAMBDA_FUNC_S3_BUCKET --region $REGION >> $log_filename
  else
    aws s3api create-bucket --bucket $LAMBDA_FUNC_S3_BUCKET --region $REGION --create-bucket-configuration LocationConstraint=$REGION >> $log_filename
  fi

  if [ $? -eq 0 ]; then
    echo "Step 5/16 : Successfully created bucket ${LAMBDA_FUNC_S3_BUCKET} in region ${REGION}."
    echo "Step 5/16 : Successfully created bucket ${LAMBDA_FUNC_S3_BUCKET} in region ${REGION}." >> $log_filename
  else
    echo "Step 5/16 : Failed to create S3 bucket ${LAMBDA_FUNC_S3_BUCKET}."
    echo "Step 5/16 : Failed to create S3 bucket ${LAMBDA_FUNC_S3_BUCKET}." >> $log_filename
  fi
fi

event_bucket_exists="false";
# Check if the bucket exists
for item in $list_of_existing_aws_s3_buckets
do
    if [ "${EVENT_S3_SOURCE_BUCKET}" == "${item}" ]; then
      event_bucket_exists="true";
    fi
done

# Check if the variable is true
if [ "$event_bucket_exists" == "true" ]; then
    echo "Step 6/16 : Bucket ${EVENT_S3_SOURCE_BUCKET} exists, skipping the creation of new bucket"
    echo "Step 6/16 : Bucket ${EVENT_S3_SOURCE_BUCKET} exists, skipping the creation of new bucket" >> $log_filename
else
  if [ "$REGION" == "us-east-1" ]; then
    aws s3api create-bucket --bucket $EVENT_S3_SOURCE_BUCKET --region $REGION >> $log_filename
  else
    aws s3api create-bucket --bucket $EVENT_S3_SOURCE_BUCKET --region $REGION --create-bucket-configuration LocationConstraint=$REGION >> $log_filename
  fi

  if [ $? -eq 0 ]; then
    echo "Step 6/16 : Successfully created bucket ${EVENT_S3_SOURCE_BUCKET} in region ${REGION}."
    echo "Step 6/16 : Successfully created bucket ${EVENT_S3_SOURCE_BUCKET} in region ${REGION}." >> $log_filename
  else
    echo "Step 6/16 : Failed to create S3 bucket ${EVENT_S3_SOURCE_BUCKET}."
    echo "Step 6/16 : Failed to create S3 bucket ${EVENT_S3_SOURCE_BUCKET}." >> $log_filename
  fi
fi

# Check if the directory exists
if [ -z "$EVENT_S3_SOURCE_KEY" ]; then
  echo "No EVENT_S3_SOURCE_KEY is specified, Event notification will be created on ${EVENT_S3_SOURCE_BUCKET} bucket"
  echo "No EVENT_S3_SOURCE_KEY is specified, Event notification will be created on ${EVENT_S3_SOURCE_BUCKET} bucket" >> $log_filename
else
  if [ -z "$(aws s3 ls "s3://${EVENT_S3_SOURCE_BUCKET}/${EVENT_S3_SOURCE_KEY}")" ]; then
    aws s3api put-object --bucket $EVENT_S3_SOURCE_BUCKET --key $EVENT_S3_SOURCE_KEY/ --region $REGION >> $log_filename
    if [ $? -eq 0 ]; then
      echo "Step 7/16 : Successfully created ${EVENT_S3_SOURCE_KEY} directory in ${EVENT_S3_SOURCE_BUCKET}."
      echo "Step 7/16 : Successfully created ${EVENT_S3_SOURCE_KEY} directory in ${EVENT_S3_SOURCE_BUCKET}." >> $log_filename
    else
      echo "Step 7/16 : Failed to create ${EVENT_S3_SOURCE_KEY} directory ${EVENT_S3_SOURCE_BUCKET}."
      echo "Step 7/16 : Failed to create ${EVENT_S3_SOURCE_KEY} directory ${EVENT_S3_SOURCE_BUCKET}." >> $log_filename
      exit
    fi

  else
    echo "Step 7/16 : ${EVENT_S3_SOURCE_KEY} directory already exists in ${EVENT_S3_SOURCE_BUCKET} bucket, skipping it's creation."
    echo "Step 7/16 : ${EVENT_S3_SOURCE_KEY} directory already exists in ${EVENT_S3_SOURCE_BUCKET} bucket, skipping it's creation." >> $log_filename
  fi

fi

IAM_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws-us-gov:iam::${AWS_ACCOUNT_ID}:role/${LAMBDA_ROLE}"
      },
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "*"
    }
  ]
}
EOF
)

echo "Step 8/16 : Successfully created policy IAM_POLICY for ${LAMBDA_ROLE} role in aws account ${AWS_ACCOUNT_ID}"
echo "Step 8/16 : Successfully created policy IAM_POLICY for ${LAMBDA_ROLE} role in aws account ${AWS_ACCOUNT_ID}" >> $log_filename

POLICY_FILE="policy.json"
echo "$IAM_POLICY" > "$POLICY_FILE"

#attach resource policy to secrete keys
aws secretsmanager put-resource-policy \
    --secret-id $CONSUMER_KEY_NAME \
    --resource-policy file://policy.json \
    --block-public-policy >> $log_filename

echo "Step 9/16 : Successfully attached policy to ${CONSUMER_KEY_NAME}"
echo "Step 9/16 : Successfully attached policy to ${CONSUMER_KEY_NAME}" >> $log_filename

aws secretsmanager put-resource-policy \
    --secret-id $RSA_PRIVATE_KEY_NAME \
    --resource-policy file://policy.json \
    --block-public-policy >> $log_filename

echo "Step 10/16 : Successfully attached policy to ${RSA_PRIVATE_KEY_NAME}"
echo "Step 10/16 : Successfully attached policy to ${RSA_PRIVATE_KEY_NAME}" >> $log_filename

# Clean up the policy file
rm "$POLICY_FILE"

aws s3 cp $SOURCE_CODE_LOCAL_PATH s3://$LAMBDA_FUNC_S3_BUCKET/$LAMBDA_FUNC_LOC_S3_KEY/

echo "Step 11/16 : Successfully uploaded source code of cloud function from ${SOURCE_CODE_LOCAL_PATH} to bucket ${LAMBDA_FUNC_S3_BUCKET}/${LAMBDA_FUNC_LOC_S3_KEY}"
echo "Step 11/16 : Successfully uploaded source code of cloud function from ${SOURCE_CODE_LOCAL_PATH} to bucket ${LAMBDA_FUNC_S3_BUCKET}/${LAMBDA_FUNC_LOC_S3_KEY}" >> $log_filename

# Check if the Lambda function exists
if aws lambda get-function --function-name "$LAMBDA_FUNC_NAME" 2>&1 | grep -q "ResourceNotFoundException"; then
    # Create the Lambda function
    aws lambda create-function --function-name $LAMBDA_FUNC_NAME \
    --runtime python3.11 \
    --handler unstructured_data.s3_events_handler \
    --role $LAMBDA_ROLE_ARN \
    --code S3Bucket=$LAMBDA_FUNC_S3_BUCKET,S3Key=$LAMBDA_FUNC_LOC_S3_KEY/$(basename "$SOURCE_CODE_LOCAL_PATH") \
    --environment "Variables={SF_LOGIN_URL=${SF_LOGIN_URL},SF_AUDIENCE_URL=${SF_AUDIENCE_URL},SF_USERNAME=${SF_USERNAME},RSA_PRIVATE_KEY=${RSA_PRIVATE_KEY_NAME},CONSUMER_KEY=${CONSUMER_KEY_NAME}}" \
    --timeout 60 >> $log_filename

    if [ $? -eq 0 ]; then
      echo "Step 12/16 : Successfully created cloud/lamda function with name ${LAMBDA_FUNC_NAME}"
      echo "Step 12/16 : Successfully created cloud/lamda function with name ${LAMBDA_FUNC_NAME}" >> $log_filename
    else
      echo "Step 12/16 : There are errors in createing function named ${LAMBDA_FUNC_NAME}, please correct and try again"
      echo "Step 12/16 : There are errors in createing function named ${LAMBDA_FUNC_NAME}, please correct and try again" >> $log_filename
      exit
    fi

else
    echo "Step 12/16 :  Lambda function ${LAMBDA_FUNC_NAME} exists, skipping the creation"
    echo "Step 12/16 :  Lambda function ${LAMBDA_FUNC_NAME} exists, skipping the creation" >> $log_filename
fi

FUNCTION_ARN=$(aws lambda get-function --function-name $LAMBDA_FUNC_NAME --query 'Configuration.FunctionArn' --output text)

echo $FUNCTION_ARN

echo "Step 13/16: Starting adding permission to invoke lambda function ${LAMBDA_FUNC_NAME} with ARN ${FUNCTION_ARN} to bucket ${EVENT_S3_SOURCE_BUCKET}"
echo "Step 13/16: Starting adding permission to invoke lambda function ${LAMBDA_FUNC_NAME} with ARN ${FUNCTION_ARN} to bucket ${EVENT_S3_SOURCE_BUCKET}" >> $log_filename

aws lambda add-permission \
  --function-name $LAMBDA_FUNC_NAME \
  --statement-id "resource_policy_${current_epoch_time}" \
  --action lambda:InvokeFunction \
  --principal s3.amazonaws.com \
  --source-arn "arn:aws-us-gov:s3:::${EVENT_S3_SOURCE_BUCKET}" \
  --source-account $AWS_ACCOUNT_ID  >> $log_filename

echo "Step 13/16: Completed adding permission to invoke lambda function ${LAMBDA_FUNC_NAME} with ARN ${FUNCTION_ARN} to bucket ${EVENT_S3_SOURCE_BUCKET}"
echo "Step 13/16: Completed adding permission to invoke lambda function ${LAMBDA_FUNC_NAME} with ARN ${FUNCTION_ARN} to bucket ${EVENT_S3_SOURCE_BUCKET}" >> $log_filename


EMPTY_EVENT_NOTIFICATION=$(cat <<EOF
{
  "LambdaFunctionConfigurations": []
}
EOF
)

NEW_EVENT_NOTIFICATION=$(cat <<EOF
{
  "Id": "Event_${current_epoch_time}",
  "LambdaFunctionArn": "${FUNCTION_ARN}",
  "Events": [
    "s3:ObjectCreated:*",
    "s3:ObjectRemoved:*"
  ],
  "Filter": {
    "Key": {
      "FilterRules": [
        {
          "Name": "Prefix",
          "Value": "${EVENT_S3_SOURCE_KEY}"
        },
        {
          "Name": "Suffix",
          "Value": ""
        }
      ]
    }
  }
}
EOF
)

# Set a temporary file to store the notification configuration
EMPTY_EVENT_NOTIFICATION_FILE="empty_notification.json"
NEW_EVENT_NOTIFICATION_FILE="new_notification.json"
EXISTING_EVENT_NOTIFICATION_FILE="existing_notification.json"
CONCATENATED_EVENT_NOTIFICATION_FILE="concatenated_notification.json"

# Write the notification configuration to the temporary file
echo "$EMPTY_EVENT_NOTIFICATION" > "$EMPTY_EVENT_NOTIFICATION_FILE"
echo "$NEW_EVENT_NOTIFICATION" > "$NEW_EVENT_NOTIFICATION_FILE"

# Get existing event notification configuration
EXISTING_EVENT_NOTIFICATION=$(aws s3api get-bucket-notification-configuration --bucket $EVENT_S3_SOURCE_BUCKET --region $REGION)

echo "Existing notification details are as below" >> $log_filename
echo "${EXISTING_EVENT_NOTIFICATION}" >> $log_filename

# Check if the existing notification configuration contains Lambda function ARN
if echo "${EXISTING_EVENT_NOTIFICATION} --query 'LambdaFunctionConfigurations[*].LambdaFunctionArn' --output text" | grep -q "arn" ; then
    echo "Lambda function-type event notification exists on bucket $EVENT_S3_SOURCE_BUCKET, appending new event notification"
    echo "Lambda function-type event notification exists on bucket $EVENT_S3_SOURCE_BUCKET, appending new event notification" >> $log_filename
    echo "$EXISTING_EVENT_NOTIFICATION" > "$EXISTING_EVENT_NOTIFICATION_FILE"
    jq '.LambdaFunctionConfigurations += [input]' $EXISTING_EVENT_NOTIFICATION_FILE $NEW_EVENT_NOTIFICATION_FILE > "$CONCATENATED_EVENT_NOTIFICATION_FILE"
else
    echo "No Lambda function-type event notification exists on bucket $EVENT_S3_SOURCE_BUCKET, Adding new event notification"
    echo "No Lambda function-type event notification exists on bucket $EVENT_S3_SOURCE_BUCKET, Adding new event notification" >> $log_filename
    jq '.LambdaFunctionConfigurations += [input]' $EMPTY_EVENT_NOTIFICATION_FILE $NEW_EVENT_NOTIFICATION_FILE > "$CONCATENATED_EVENT_NOTIFICATION_FILE"
fi

echo "Concatenated notification details are as below" >> $log_filename
echo "$(cat ${CONCATENATED_EVENT_NOTIFICATION_FILE})" >> $log_filename

# Create the S3 bucket event notification
aws s3api put-bucket-notification-configuration \
  --bucket $EVENT_S3_SOURCE_BUCKET \
  --notification-configuration file://$CONCATENATED_EVENT_NOTIFICATION_FILE >> $log_filename

echo "Step 14/16 : Successfully created S3 bucket event notification for bucket - ${EVENT_S3_SOURCE_BUCKET}"
echo "Step 14/16 : Successfully created S3 bucket event notification for bucket - ${EVENT_S3_SOURCE_BUCKET}" >> $log_filename

aws iam attach-role-policy --role-name $LAMBDA_ROLE \
 --policy-arn arn:aws-us-gov:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole >> $log_filename

echo "Step 15/16 : Successfully attached ${LAMBDA_ROLE} to upload logs to CloudWatch"
echo "Step 15/16 : Successfully attached ${LAMBDA_ROLE} to upload logs to CloudWatch" >> $log_filename

#waiting 300 seconds for policy to be attached to lambda function, else the first file will be missed
sleep 300

#validate the configuration setup
if echo "$(aws lambda invoke --function-name $LAMBDA_FUNC_NAME response.json --output text)" 2>&1 | grep -q "200" ; then
  echo "Step 16/16 : Event notification configuration on ${EVENT_S3_SOURCE_BUCKET} bucket is Successful"
  echo "Step 16/16 : Event notification configuration on ${EVENT_S3_SOURCE_BUCKET} bucket is Successful" >> $log_filename
else
  echo "Step 16/16 : Event notification configuration on ${EVENT_S3_SOURCE_BUCKET} bucket is not Successful"
  echo "Step 16/16 : Event notification configuration on ${EVENT_S3_SOURCE_BUCKET} bucket is not Successful" >> $log_filename
fi

echo "All the s3 cloud function installer logs are logged to ${log_filename} file"

#backup remove temp files
mv $NEW_EVENT_NOTIFICATION_FILE new_notification_bkp.json
mv $CONCATENATED_EVENT_NOTIFICATION_FILE concatenated_notification_bkp.json
if [ -e "$EXISTING_EVENT_NOTIFICATION_FILE" ]; then
  mv $EXISTING_EVENT_NOTIFICATION_FILE existing_notification_bkp.json
fi
rm $EMPTY_EVENT_NOTIFICATION_FILE

echo "AWS/S3 EVENT NOTIFICATION SUCCESSFUL - Below is the summary of important resources"
echo "EVENT S3 SOURCE BUCKET NAME: ${EVENT_S3_SOURCE_BUCKET}"
echo "EVENT S3 SOURCE KEY / FOLDER NAME (with in ${EVENT_S3_SOURCE_BUCKET} bucket) : ${EVENT_S3_SOURCE_KEY}"
echo "LAMBDA FUNCTION SOURCE CODE S3 BUCKET: ${LAMBDA_FUNC_S3_BUCKET}"
echo "LAMBDA FUNCTION SOURCE CODE SOURCE KEY / FOLDER NAME (with in ${LAMBDA_FUNC_S3_BUCKET} bucket) : ${LAMBDA_FUNC_LOC_S3_KEY}"
echo "CONSUMER KEY : ${CONSUMER_KEY_NAME}"
echo "RSA PRIVATE KEY NAME : ${RSA_PRIVATE_KEY_NAME}"
echo "LAMBDA FUNCTION NAME : ${LAMBDA_FUNC_NAME}"
echo "LAMBDA ROLE ARN : ${LAMBDA_ROLE_ARN}"
echo "REGION : ${REGION}"
echo "Event Notification Name : Event_${current_epoch_time}"
echo "As a next step, you can create the relevant parent and second level directories (if they don't exist) in the above ${EVENT_S3_SOURCE_BUCKET}/${EVENT_S3_SOURCE_KEY} such that they align with the parent directory in aws/s3 connector and the directory mentioned while UDLO creation"