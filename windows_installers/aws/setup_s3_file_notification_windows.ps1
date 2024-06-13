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

#edit the input_parameters_s3_windows.txt file with respective environment variables
#export JIT credentials into terminal before running it or perform run 'aws configure' in your terminal
#run this file with command ".\setup_s3_file_notification_windows.ps1 -ConfigFile input_parameters_s3_windows.txt"
#make sure you have the credentials of the aws admin role

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
$SF_USERNAME = $configuration["SF_USERNAME"]
$SF_LOGIN_URL = $configuration["SF_LOGIN_URL"]
$AWS_ACCOUNT_ID = $configuration["AWS_ACCOUNT_ID"]
$REGION = $configuration["REGION"]
$EVENT_S3_SOURCE_BUCKET = $configuration["EVENT_S3_SOURCE_BUCKET"]
$EVENT_S3_SOURCE_KEY = $configuration["EVENT_S3_SOURCE_KEY"]
$LAMBDA_FUNC_S3_BUCKET = $configuration["LAMBDA_FUNC_S3_BUCKET"]
$LAMBDA_FUNC_LOC_S3_KEY = $configuration["LAMBDA_FUNC_LOC_S3_KEY"]
$SOURCE_CODE_LOCAL_PATH = $configuration["SOURCE_CODE_LOCAL_PATH"]
$LAMBDA_ROLE = $configuration["LAMBDA_ROLE"]
$LAMBDA_FUNC_NAME = $configuration["LAMBDA_FUNC_NAME"]
$CONSUMER_KEY_NAME = $configuration["CONSUMER_KEY_NAME"]
$CONSUMER_KEY_VALUE = $configuration["CONSUMER_KEY_VALUE"]
$RSA_PRIVATE_KEY_NAME = $configuration["RSA_PRIVATE_KEY_NAME"]
$PEM_FILE_PATH = $configuration["PEM_FILE_PATH"]

# Display configuration values
Write-Host "Environment Variables are set as below"
Write-Host "SF_USERNAME: $SF_USERNAME"
Write-Host "SF_LOGIN_URL: $SF_LOGIN_URL"
Write-Host "AWS_ACCOUNT_ID: $AWS_ACCOUNT_ID"
Write-Host "REGION: $REGION"
Write-Host "EVENT_S3_SOURCE_BUCKET: $EVENT_S3_SOURCE_BUCKET"
Write-Host "EVENT_S3_SOURCE_KEY: $EVENT_S3_SOURCE_KEY"
Write-Host "LAMBDA_FUNC_S3_BUCKET: $LAMBDA_FUNC_S3_BUCKET"
Write-Host "LAMBDA_FUNC_LOC_S3_KEY: $LAMBDA_FUNC_LOC_S3_KEY"
Write-Host "SOURCE_CODE_LOCAL_PATH: $SOURCE_CODE_LOCAL_PATH"
Write-Host "LAMBDA_ROLE: $LAMBDA_ROLE"
Write-Host "LAMBDA_FUNC_NAME: $LAMBDA_FUNC_NAME"
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
    $user_input = Read-Host "Have you added/configured aws credentials of admin role to terminal, It is a must to have admin role credentials? (yes/no)"
    if ($user_input -eq "yes") {
        break
    }
    elseif ($user_input -eq "no") {
        Write-Host "Please add/configure aws credentials of admin role in terminal before running this script or add below policy to your iam user which has access to your bucket"
        Write-HOST "
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
        }"
    exit
    }
    else{
        Write-Host "Invalid input. Please enter 'yes' or 'no'."
        continue
    }
}

while ($true) {
    $user_input = Read-Host "Have you downloaded the source code for cloud function from https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/cloud_function_zips/aws_lambda_function.zip into your local machine? (yes/no)"
    if ($user_input -eq "yes") {
        break
    }
    elseif ($user_input -eq "no") {
        Write-Host "Please download source code zip from https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/cloud_function_zips/aws_lambda_function.zip"
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
    2. Downloading of aws_lambda_function.zip
    3. Generating and exporting valid AWS credentials (AWS_ACCESS_KEY, AWS_SECRETE_ACCESS_KEY and AWS_SESSION_TOKEN) with admin access to the terminal
    4. Updating parameters in the configuration file input_parameters_s3_windows.txt
    5. renaming keypair.key to keypair.pem (one of the keys generated during pre-requiste step of connected app creation)
    6. AWS CLI and powershell installation
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
    $user_input = Read-Host "Running this script will create new s3 bucket and the folder/s3 key (if it does not exists) and setup file event notification on it. Agree to proceed? (yes/no)"
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


$awsCliVersion = aws --version 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "AWS CLI is installed. Version: $awsCliVersion"
} else {
    Write-Host "AWS CLI is not installed, please install AWS CLI for windows from https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
}


$currentDateTime = Get-Date -Format "yyyyMMdd_HHmmss"
$log_filename = "logfile_$currentDateTime.txt"

Write-Host "All the aws cloud function installer logs are logged to $log_filename file"

$validation_errors = @()

# Function to add an error to the array
function add_validation_error {
    param (
        [string] $validation_error
    )
  $Script:validation_errors += $validation_error
}

function is_aws_credentials_configured {
   # Check if all three AWS environment variables are set
    if ($Env:AWS_ACCESS_KEY_ID -and $Env:AWS_SECRET_ACCESS_KEY -and $Env:AWS_SESSION_TOKEN) {
        Write-Output "All AWS environment variables are set."
    } else {
        Write-Output "One or more AWS environment variables are NOT set."

        if (-not $Env:AWS_ACCESS_KEY_ID) {
            Write-Output "AWS_ACCESS_KEY_ID is NOT set."
        }

        if (-not $Env:AWS_SECRET_ACCESS_KEY) {
            Write-Output "AWS_SECRET_ACCESS_KEY is NOT set."
        }

        if (-not $Env:AWS_SESSION_TOKEN) {
            Write-Output "AWS_SESSION_TOKEN is NOT set."
        }

        exit
    }
}

function is_aws_credentials_valid {
    try {
        # Make a call to AWS to describe the current user
        aws sts get-caller-identity > $null
        Write-Host "AWS credentials entered in terminal are valid"
        "AWS credentials entered in terminal are valid" | Out-File -FilePath $log_filename -Append
    }
    catch {
        add_validation_error "Error: Security credentials/tokens are either expired or invalid and please use valid security tokens"

        "Error: Security credentials/tokens are either expired or invalid and please use valid security tokens" | Out-File -FilePath $log_filename -Append

        exit
    }
}

# Function to check if a string is a valid AWS region
function is_valid_region {
    if ($REGION -ne $null) {
        if ($REGION) {
            Write-Host "Variable REGION has a value"
            "Variable REGION has a value" | Out-File -FilePath $log_filename -Append
        } else {
            add_validation_error "Variable REGION does not has no value"
            "Variable REGION does not have value" | Out-File -FilePath $log_filename -Append
        }
    } else {
        add_validation_error "REGION does not exist"
        "Variable REGION does not exist" | Out-File -FilePath $log_filename -Append
    }

    # Get the list of AWS regions
    $validRegions = Get-AWSRegion | Select-Object -ExpandProperty Region

   if ($validRegions -contains $REGION) {
        Write-Host "${REGION} is a valid region"
        "${REGION} is a valid region" | Out-File -FilePath $log_filename -Append
    } else {
        add_validation_error "${REGION} region is invalid, please use a valid region"
        "${REGION} region is invalid, please use a valid region" | Out-File -FilePath $log_filename -Append
    }
}

function is_s3_bucket_name_variables_exist {
    if ($EVENT_S3_SOURCE_BUCKET -ne $null) {
        if ($EVENT_S3_SOURCE_BUCKET) {
            Write-Host "Variable EVENT_S3_SOURCE_BUCKET has a value"
            "Variable EVENT_S3_SOURCE_BUCKET has a value" | Out-File -FilePath $log_filename -Append
        } else {
            add_validation_error "Variable EVENT_S3_SOURCE_BUCKET does not has no value"
            "Variable EVENT_S3_SOURCE_BUCKET does not have value" | Out-File -FilePath $log_filename -Append
        }
    } else {
        add_validation_error "EVENT_S3_SOURCE_BUCKET does not exist"
        "Variable EVENT_S3_SOURCE_BUCKET does not exist" | Out-File -FilePath $log_filename -Append
    }

    if ($LAMBDA_FUNC_S3_BUCKET -ne $null) {
        if ($LAMBDA_FUNC_S3_BUCKET) {
            Write-Host "Variable LAMBDA_FUNC_S3_BUCKET has a value"
            "Variable LAMBDA_FUNC_S3_BUCKET has a value" | Out-File -FilePath $log_filename -Append
        } else {
            add_validation_error "Variable LAMBDA_FUNC_S3_BUCKET does not has no value"
            "Variable LAMBDA_FUNC_S3_BUCKET does not have value" | Out-File -FilePath $log_filename -Append
        }
    } else {
        add_validation_error "LAMBDA_FUNC_S3_BUCKET does not exist"
        "Variable LAMBDA_FUNC_S3_BUCKET does not exist" | Out-File -FilePath $log_filename -Append
    }
}

# Function to check if a string is a valid S3 bucket name
function is_valid_s3_bucket_name {
    param (
        [string] $bucketName
    )
    # Length constraint
    if ($bucketName.Length -lt 3 -or $bucketName.Length -gt 63) {
        add_validation_error "Error: Invalid bucket name : ${bucketName}. Length must be between 1 and 64 characters."

        "Error: Invalid bucket name : ${bucketName}. Length must be between 1 and 64 characters." | Out-File -FilePath $log_filename -Append
    }

    # Regex pattern to match lowercase letters, numbers, hyphens, and dots
    $pattern = "^[a-z0-9]+([\-\.]?[a-z0-9]+)*$"

    # Check if the bucket name matches the pattern
    if ($bucketName -match $pattern) {
        # Check if it starts and ends with a letter or number
        if ($bucketName -cmatch "^[a-z0-9].*[a-z0-9]$") {
            # Check if it's not an IP address
            if (-not ($bucketName -as [IPAddress])) {
                Write-Host "$bucketName is a valid bucket name"
                "$bucketName is a valid bucket name" | Out-File -FilePath $log_filename -Append
            }
        }
    } else{
        add_validation_error "Error: Invalid AWS S3 bucket name: ${s3_bucket_name}, Only lowercase alphanumeric characters, hyphens, and dots are allowed"

        "Error: Invalid AWS S3 bucket name: ${s3_bucket_name}, Only lowercase alphanumeric characters, hyphens, and dots are allowed" | Out-File -FilePath $log_filename -Append
    }
}

function is_valid_folder_name_in_s3_bucket {
   param (
        [string] $bucketName,
        [string] $foldername
    )
    # Define the regex pattern
    $regex = "^[a-zA-Z0-9].*[a-zA-Z0-9]$"

    # Check if the string matches the regex
    if ($foldername -match $regex) {
        Write-Host "${foldername} folder name with in ${bucketName} bucket is valid which starts with an alphanumeric character and ends with an alphanumeric character."

        "${foldername} folder name with in ${bucketName} bucket is valid which starts with an alphanumeric character and ends with an alphanumeric character." | Out-File -FilePath $log_filename -Append
    } else {
        add_validation_error "Error: ${foldername} folder name with in ${bucketName} bucket is invalid, folder name should start and end with alphanumeric characters"

        "Error: ${foldername} folder name with in ${bucketName} bucket is invalid, folder name should start and end with alphanumeric characters" | Out-File -FilePath $log_filename -Append
    }
}


# Function to check if a string is a valid IAM role name
function is_valid_lambda_role_name {

    if ($LAMBDA_ROLE -ne $null) {
        if ($LAMBDA_ROLE) {
            Write-Host "Variable LAMBDA_ROLE has a value"
            "Variable LAMBDA_ROLE has a value" | Out-File -FilePath $log_filename -Append
        } else {
            add_validation_error "Variable LAMBDA_ROLE does not has no value"
            "Variable LAMBDA_ROLE does not have value" | Out-File -FilePath $log_filename -Append
        }
    } else {
        add_validation_error "LAMBDA_ROLE does not exist"
        "Variable LAMBDA_ROLE does not exist" | Out-File -FilePath $log_filename -Append
    }

    # Length constraint
    if ($LAMBDA_ROLE.Length -lt 1 -or $LAMBDA_ROLE.Length -gt 128) {

        add_validation_error "Error: Invalid LAMBDA_ROLE or IAM role name: ${LAMBDA_ROLE}. Length must be between 1 and 128 characters."

        "Error: Invalid LAMBDA_ROLE or IAM role name: ${LAMBDA_ROLE}. Length must be between 1 and 128 characters." | Out-File -FilePath $log_filename -Append
    }

    # Regex pattern to match valid IAM role names
    $pattern = "^[a-zA-Z0-9+=,.@-]+$"

    # Check if the role name matches the pattern
    if ($LAMBDA_ROLE -match $pattern) {
        # Check if it doesn't end with ., @, or -
        if (-not ($LAMBDA_ROLE.EndsWith(".") -or $LAMBDA_ROLE.EndsWith("@") -or $LAMBDA_ROLE.EndsWith("-"))) {
            Write-Host "$LAMBDA_ROLE is valid IAM_ROLE name"
            "$LAMBDA_ROLE is valid IAM_ROLE name" | Out-File -FilePath $log_filename -Append
        }
    }else{
        add_validation_error "Error: Invalid LAMBDA_ROLE or IAM role name: ${LAMBDA_ROLE}. Only alphanumeric characters, hyphens, underscores, commas, periods, at signs (@), and the plus sign (+) are allowed."

        "Error: Invalid LAMBDA_ROLE or IAM role name: ${LAMBDA_ROLE}. Only alphanumeric characters, hyphens, underscores, commas, periods, at signs (@), and the plus sign (+) are allowed." | Out-File -FilePath $log_filename -Append
    }
}

function is_valid_aws_secret_key_name {
   param (
        [string] $keyName
    )

     # Length constraint
    if ($keyName.Length -eq 0 -or $keyName.Length -gt 255) {
       add_validation_error "Invalid AWS secret key name - $aws_secret_key_name. Either CONSUMER_KEY or RSA_PRIVATE_KEY name is less than 0 or more than 255 characters in length"

       "Invalid AWS secret key name - $aws_secret_key_name. Either CONSUMER_KEY or RSA_PRIVATE_KEY name is less than 0 or more than 255 characters in length" | Out-File -FilePath $log_filename -Append
    }

    # Regex pattern to match valid secret key names
    $pattern = "^[a-zA-Z0-9-_]+$"

    # Check if the key name matches the pattern
    if ($keyName -match $pattern) {
        Write-Host "CONSUMER_KEY or RSA_PRIVATE_KEY is valid"
        "CONSUMER_KEY or RSA_PRIVATE_KEY is valid" | Out-File -FilePath $log_filename -Append
    } else {
        add_validation_error "Invalid AWS secret key name - $aws_secret_key_name. Either CONSUMER_KEY or RSA_PRIVATE_KEY name is invaid, It may contain only alphanumeric characters and the characters /_+=-."

        "Invalid AWS secret key name - $aws_secret_key_name. Either CONSUMER_KEY or RSA_PRIVATE_KEY name is invaid, It may contain only alphanumeric characters and the characters /_+=-." | Out-File -FilePath $log_filename -Append
    }
}

function is_valid_source_code_local_path {

    if ($SOURCE_CODE_LOCAL_PATH -eq "" -or $SOURCE_CODE_LOCAL_PATH -eq $null) {
       add_validation_error "Error: Source code local path is missing/empty. Please provide a valid Source code local path and source code zip can be downloaded from https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/cloud_function_zips/azure_function_app.zip"

       "Error: Source code local path is missing/empty. Please provide a valid Source code local path and source code zip can be downloaded from https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/cloud_function_zips/azure_function_app.zip" | Out-File -FilePath $log_filename -Append
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

# Function to check if a string is a valid Lambda function name
function is_valid_lambda_func_name {

    if ($LAMBDA_FUNC_NAME -ne $null) {
        if ($LAMBDA_FUNC_NAME) {
            Write-Host "Variable LAMBDA_FUNC_NAME has a value"
            "Variable LAMBDA_FUNC_NAME has a value" | Out-File -FilePath $log_filename -Append
        } else {
            add_validation_error "Variable LAMBDA_FUNC_NAME does not has no value"
            "Variable LAMBDA_FUNC_NAME does not have value" | Out-File -FilePath $log_filename -Append
        }
    } else {
        add_validation_error "LAMBDA_FUNC_NAME does not exist"
        "Variable LAMBDA_FUNC_NAME does not exist" | Out-File -FilePath $log_filename -Append
    }


    # Length constraint
    if ($LAMBDA_FUNC_NAME.Length -lt 1 -or $LAMBDA_FUNC_NAME.Length -gt 64) {
        add_validation_error "Invalid Lambda function name: $lambda_func_name. Length must be between 1 and 64 characters."
        "Invalid Lambda function name: $lambda_func_name. Length must be between 1 and 64 characters." | Out-File -FilePath $log_filename -Append
    }

    # Regex pattern to match valid Lambda function names
    $pattern = "^[a-zA-Z0-9]+[a-zA-Z0-9-_]*[a-zA-Z0-9]+$"

    # Check if the function name matches the pattern
    if ($LAMBDA_FUNC_NAME -match $pattern) {
        Write-Host "$LAMBDA_FUNC_NAME is a valid Lambda function name."
        "$LAMBDA_FUNC_NAME is a valid Lambda function name." | Out-File -FilePath $log_filename -Append
    } else {

        add_validation_error "Invalid Lambda function name: $LAMBDA_FUNC_NAME. Only alphanumeric characters, hyphens, and underscores are allowed."

        "Invalid Lambda function name: $LAMBDA_FUNC_NAME. Only alphanumeric characters, hyphens, and underscores are allowed." | Out-File -FilePath $log_filename -Append
    }
}

# Check if AWSPowerShell.NetCore module is installed
if (-not (Get-Module -ListAvailable -Name AWSPowerShell.NetCore)) {
    Write-Output "Installing AWS Tools for PowerShell..."
    Install-Module -Name AWSPowerShell.NetCore -Scope CurrentUser -Force
} else {
    Write-Output "AWS Tools for PowerShell is already installed."
}

is_aws_credentials_configured
is_aws_credentials_valid
is_valid_region
is_s3_bucket_name_variables_exist
is_valid_s3_bucket_name $EVENT_S3_SOURCE_BUCKET
is_valid_s3_bucket_name $LAMBDA_FUNC_S3_BUCKET
is_valid_folder_name_in_s3_bucket $EVENT_S3_SOURCE_KEY $EVENT_S3_SOURCE_BUCKET
is_valid_folder_name_in_s3_bucket $LAMBDA_FUNC_LOC_S3_KEY $LAMBDA_FUNC_S3_BUCKET
is_valid_lambda_role_name
is_valid_aws_secret_key_name $CONSUMER_KEY_NAME
is_valid_aws_secret_key_name $RSA_PRIVATE_KEY_NAME
is_valid_source_code_local_path
is_valid_pem_file_path
is_valid_lambda_func_name

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
    Write-Host "NOTE: Please check descriptions of each variable in https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/installers/aws/input_parameters_s3.conf"

    "NOTE: Please check descriptions of each variable in https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/installers/aws/input_parameters_s3.conf" | Out-File -FilePath $log_filename -Append

    exit
}

Write-Host "Step 1/14 : Successfully logged into AWS"
"Step 1/14 : Successfully logged into AWS" | Out-File -FilePath $log_filename -Append

aws configure set region $REGION
aws configure set output "json"

$currentEpochTime = [int][double]::Parse((Get-Date -UFormat %s))

try {
    $role = Get-IAMRole -RoleName $LAMBDA_ROLE -ErrorAction Stop
    Write-Output "Step 2/14 : iam-role with name ${LAMBDA_ROLE} already exists, skipping creation"
} catch {
    '{"Version": "2012-10-17","Statement": [{ "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}' | Set-Content NewRoleTrustPolicy.json

    $createOutput = New-IAMRole -AssumeRolePolicyDocument (Get-Content -raw NewRoleTrustPolicy.json) -RoleName $LAMBDA_ROLE

    # Check if the output contains information about the created storage account
    if ($createOutput) {
        Write-Host "Step 2/14 : Successfully created iam-role with name ${LAMBDA_ROLE}"
        "Step 2/14 : Successfully created iam-role with name ${LAMBDA_ROLE}" | Out-File -FilePath $log_filename -Append
    } else {
         Write-Host "Step 2/14 : Failed to create iam-role with name ${LAMBDA_ROLE}"
         "Step 2/14 : Failed to create iam-role with name ${LAMBDA_ROLE}" | Out-File -FilePath $log_filename -Append
         exit
    }
}

$LAMBDA_ROLE_ARN=$(aws iam get-role --role-name $LAMBDA_ROLE --query 'Role.Arn' --output text)

Write-Host "LAMBDA_ROLE_ARN : ${LAMBDA_ROLE_ARN}"
"LAMBDA_ROLE_ARN : ${LAMBDA_ROLE_ARN}" | Out-File -FilePath $log_filename -Append

try {
    Get-SECSecretValue -SecretId $CONSUMER_KEY_NAME -ErrorAction Stop
    Write-Output "Step 3/14 : ${CONSUMER_KEY_NAME} already exists, skipping the creation"
    "Step 3/14 : ${CONSUMER_KEY_NAME} already exists, skipping the creation" | Out-File -FilePath $log_filename -Append
} catch {
    $consumerKeyCreateOutput = aws secretsmanager create-secret --name $CONSUMER_KEY_NAME --secret-string $CONSUMER_KEY_VALUE
    if ($consumerKeyCreateOutput) {
        Write-Host "Step 3/14 : Secrete Key with name $CONSUMER_KEY_NAME created successfully."
        "Step 3/14 : Secrete Key with name $CONSUMER_KEY_NAME created successfully." | Out-File -FilePath $log_filename -Append
    } else {
         Write-Host "Step 3/14 : Failed to create secrete Key with name $CONSUMER_KEY_NAME."
         "Step 3/14 : Failed to create secrete Key with name $CONSUMER_KEY_NAME." | Out-File -FilePath $log_filename -Append
         exit
    }
}

try {
    Get-SECSecretValue -SecretId $RSA_PRIVATE_KEY_NAME -ErrorAction Stop
    Write-Output "Step 4/14 : ${RSA_PRIVATE_KEY_NAME} already exists, skipping the creation"
    "Step 4/14 : ${RSA_PRIVATE_KEY_NAME} already exists, skipping the creation" | Out-File -FilePath $log_filename -Append
} catch {
    $rsaKeyCreateOutput = aws secretsmanager create-secret --name $RSA_PRIVATE_KEY_NAME --secret-string file://${PEM_FILE_PATH}
    if ($rsaKeyCreateOutput) {
        Write-Host "Step 4/14 : Secrete Key with name $RSA_PRIVATE_KEY_NAME created successfully."
        "Step 4/14 : Secrete Key with name $RSA_PRIVATE_KEY_NAME created successfully." | Out-File -FilePath $log_filename -Append
    } else {
         Write-Host "Step 4/14 : Failed to create secrete Key with name $RSA_PRIVATE_KEY_NAME."
         "Step 4/14 : Failed to create secrete Key with name $RSA_PRIVATE_KEY_NAME." | Out-File -FilePath $log_filename -Append
         exit
    }
}

if (Test-S3Bucket -BucketName ${LAMBDA_FUNC_S3_BUCKET}) {
    Write-Host "Step 5/14 : Bucket ${LAMBDA_FUNC_S3_BUCKET} exists, skipping the creation of new bucket"
    "Step 5/14 : Bucket ${LAMBDA_FUNC_S3_BUCKET} exists, skipping the creation of new bucket" | Out-File -FilePath $log_filename -Append
} else{
    # Create the S3 bucket
    $lambdaBucketCreateOutpt = New-S3Bucket -BucketName $LAMBDA_FUNC_S3_BUCKET -Region $REGION
    if ($lambdaBucketCreateOutpt) {
        Write-Host "Step 5/14 : Successfully created bucket ${LAMBDA_FUNC_S3_BUCKET} in region ${REGION}."
        "Step 5/14 : Successfully created bucket ${LAMBDA_FUNC_S3_BUCKET} in region ${REGION}." | Out-File -FilePath $log_filename -Append
    } else {
        Write-Host "Step 5/14 : Failed to create S3 bucket ${LAMBDA_FUNC_S3_BUCKET}."
        "Step 5/14 : Failed to create S3 bucket ${LAMBDA_FUNC_S3_BUCKET}." | Out-File -FilePath $log_filename -Append
            exit
    }
}

if(Test-S3Bucket -BucketName ${EVENT_S3_SOURCE_BUCKET}) {
    Write-Host "Step 6/14 : Bucket ${EVENT_S3_SOURCE_BUCKET} exists, skipping the creation of new bucket"
    "Step 6/14 : Bucket ${EVENT_S3_SOURCE_BUCKET} exists, skipping the creation of new bucket" | Out-File -FilePath $log_filename -Append
} else {
    # Create the S3 bucket
    $eventBucketCreateOutpt = New-S3Bucket -BucketName $EVENT_S3_SOURCE_BUCKET -Region $REGION
    if ($eventBucketCreateOutpt) {
        Write-Host "Step 6/14 : Successfully created bucket ${EVENT_S3_SOURCE_BUCKET} in region ${REGION}."
        "Step 6/14 : Successfully created bucket ${EVENT_S3_SOURCE_BUCKET} in region ${REGION}." | Out-File -FilePath $log_filename -Append
    } else {
        Write-Host "Step 6/14 : Failed to create S3 bucket ${EVENT_S3_SOURCE_BUCKET}."
        "Step 6/14 : Failed to create S3 bucket ${EVENT_S3_SOURCE_BUCKET}." | Out-File -FilePath $log_filename -Append
        exit
    }
}


$eventS3SourceKeyExists= aws s3 ls s3://${EVENT_S3_SOURCE_BUCKET}/${EVENT_S3_SOURCE_KEY}
if($eventS3SourceKeyExists.count -gt 1) {
Write-Host "Step 7/14 : ${EVENT_S3_SOURCE_KEY} directory already exists in ${EVENT_S3_SOURCE_BUCKET} bucket, skipping it's creation."
    "Step 7/14 : ${EVENT_S3_SOURCE_KEY} directory already exists in ${EVENT_S3_SOURCE_BUCKET} bucket, skipping it's creation." | Out-File -FilePath $log_filename -Append
} else {
    if ($EVENT_S3_SOURCE_KEY -ne $null) {
        if ($EVENT_S3_SOURCE_KEY) {
            $eventBucketFolderCreateOutpt = aws s3api put-object --bucket $EVENT_S3_SOURCE_BUCKET --key $EVENT_S3_SOURCE_KEY/ --region $REGION

            if ($eventBucketFolderCreateOutpt) {
                Write-Host "Step 7/14 : Successfully created ${EVENT_S3_SOURCE_KEY} directory in ${EVENT_S3_SOURCE_BUCKET}."
                "Step 7/14 : Successfully created ${EVENT_S3_SOURCE_KEY} directory in ${EVENT_S3_SOURCE_BUCKET}." | Out-File -FilePath $log_filename -Append
            } else {
                Write-Host "Step 7/14 : Failed to create ${EVENT_S3_SOURCE_KEY} directory in ${EVENT_S3_SOURCE_BUCKET} bucket."
                "Step 7/14 : Failed to create ${EVENT_S3_SOURCE_KEY} directory ${EVENT_S3_SOURCE_BUCKET}." | Out-File -FilePath $log_filename -Append
                exit
            }
        } else {
            Write-Host "Step 7/14 : No EVENT_S3_SOURCE_KEY is specified, Event notification will be created on ${EVENT_S3_SOURCE_BUCKET} bucket"
            "Step 7/14 : No EVENT_S3_SOURCE_KEY is specified, Event notification will be created on ${EVENT_S3_SOURCE_BUCKET} bucket" | Out-File -FilePath $log_filename -Append
        }
    } else {
        Write-Host "Step 7/14 : EVENT_S3_SOURCE_KEY does not exist"
        "Step 7/14 : EVENT_S3_SOURCE_KEY does not exist" | Out-File -FilePath $log_filename -Append
    }
}

# Define the IAM policy
$IAM_POLICY = @"
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS": "arn:aws:iam::${AWS_ACCOUNT_ID}:role/${LAMBDA_ROLE}"},"Action":"secretsmanager:GetSecretValue","Resource": "*"}]}
"@

$IAM_POLICY_FILE_PATH = "policy.json"
Set-Content -Path $IAM_POLICY_FILE_PATH -Value $IAM_POLICY

Write-Host "Step 8/14 : Successfully created policy IAM_POLICY for ${LAMBDA_ROLE} role in aws account ${AWS_ACCOUNT_ID}"

"Step 8/14 : Successfully created policy IAM_POLICY for ${LAMBDA_ROLE} role in aws account ${AWS_ACCOUNT_ID}" | Out-File -FilePath $log_filename -Append

aws secretsmanager put-resource-policy --secret-id $CONSUMER_KEY_NAME --resource-policy file://$IAM_POLICY_FILE_PATH

Write-Host "Step 9/14 : Successfully attached policy to ${CONSUMER_KEY_NAME}"
"Step 9/14 : Successfully attached policy to ${CONSUMER_KEY_NAME}" | Out-File -FilePath $log_filename -Append

aws secretsmanager put-resource-policy --secret-id $RSA_PRIVATE_KEY_NAME --resource-policy file://$IAM_POLICY_FILE_PATH

Write-Host "Step 10/14 : Successfully attached policy to ${RSA_PRIVATE_KEY_NAME}"
"Step 10/14 : Successfully attached policy to ${RSA_PRIVATE_KEY_NAME}" | Out-File -FilePath $log_filename -Append

aws s3 cp $SOURCE_CODE_LOCAL_PATH s3://$LAMBDA_FUNC_S3_BUCKET/$LAMBDA_FUNC_LOC_S3_KEY/

Write-Host "Step 11/14 : Successfully uploaded source code of cloud function from ${SOURCE_CODE_LOCAL_PATH} to bucket ${LAMBDA_FUNC_S3_BUCKET}/${LAMBDA_FUNC_LOC_S3_KEY}"

"Step 11/14 : Successfully uploaded source code of cloud function from ${SOURCE_CODE_LOCAL_PATH} to bucket ${LAMBDA_FUNC_S3_BUCKET}/${LAMBDA_FUNC_LOC_S3_KEY}" | Out-File -FilePath $log_filename -Append

$lambdaFunctions = $(Get-LMFunctionList | Select-Object FunctionName)

function Test-LambdaFunctionExists {
    foreach ($function in $lambdaFunctions.FunctionName) {
        if($function -eq $LAMBDA_FUNC_NAME) {
            return $true
        }
    }
    return $false
}

if (Test-LambdaFunctionExists){
    Write-Host "Step 12/14 :  Lambda function ${LAMBDA_FUNC_NAME} exists, skipping the creation"
    "Step 12/14 : Lambda function ${LAMBDA_FUNC_NAME} exists, skipping the creation" | Out-File -FilePath $log_filename -Append
}else{
    $lambdaFunctionCreateOutput = aws lambda create-function --function-name $LAMBDA_FUNC_NAME --runtime python3.11 --handler unstructured_data.s3_events_handler --role $LAMBDA_ROLE_ARN --code S3Bucket=$LAMBDA_FUNC_S3_BUCKET,S3Key=$LAMBDA_FUNC_LOC_S3_KEY/$(Split-Path -Path $SOURCE_CODE_LOCAL_PATH -Leaf) --environment "Variables={SF_LOGIN_URL=${SF_LOGIN_URL},SF_USERNAME=${SF_USERNAME},RSA_PRIVATE_KEY=${RSA_PRIVATE_KEY_NAME},CONSUMER_KEY=${CONSUMER_KEY_NAME}}" --timeout 60

    if ($lambdaFunctionCreateOutput) {
        Write-Host "Step 12/14 : Successfully created cloud/lamda function with name ${LAMBDA_FUNC_NAME}"
        "Step 12/14 : Successfully created cloud/lamda function with name ${LAMBDA_FUNC_NAME}" | Out-File -FilePath $log_filename -Append
    }else{
        Write-Host "Step 12/14 : There are errors in createing function named ${LAMBDA_FUNC_NAME}, please correct and try again"
        "Step 12/14 : There are errors in createing function named ${LAMBDA_FUNC_NAME}, please correct and try again" | Out-File -FilePath $log_filename -Append
        exit
    }
}

$FUNCTION_ARN=$(aws lambda get-function --function-name $LAMBDA_FUNC_NAME --query 'Configuration.FunctionArn' --output text)

Write-Host  $FUNCTION_ARN

Write-Host "Step 13/14: Starting adding permission to invoke lambda function ${LAMBDA_FUNC_NAME} with ARN ${FUNCTION_ARN} to bucket ${EVENT_S3_SOURCE_BUCKET}"
"Step 13/14: Starting adding permission to invoke lambda function ${LAMBDA_FUNC_NAME} with ARN ${FUNCTION_ARN} to bucket ${EVENT_S3_SOURCE_BUCKET}" | Out-File -FilePath $log_filename -Append

aws lambda add-permission --function-name $LAMBDA_FUNC_NAME --statement-id "resource_policy_${currentEpochTime}" --action lambda:InvokeFunction --principal s3.amazonaws.com --source-arn "arn:aws:s3:::${EVENT_S3_SOURCE_BUCKET}" --source-account $AWS_ACCOUNT_ID

echo "Step 13/14: Completed adding permission to invoke lambda function ${LAMBDA_FUNC_NAME} with ARN ${FUNCTION_ARN} to bucket ${EVENT_S3_SOURCE_BUCKET}"
echo "Step 13/14: Completed adding permission to invoke lambda function ${LAMBDA_FUNC_NAME} with ARN ${FUNCTION_ARN} to bucket ${EVENT_S3_SOURCE_BUCKET}" >> $log_filename

aws iam attach-role-policy --role-name $LAMBDA_ROLE --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole | Out-File -FilePath $log_filename -Append

Write-Host "Step 14/14 : Successfully attached ${LAMBDA_ROLE} to upload logs to CloudWatch"
"Step 14/14 : Successfully attached ${LAMBDA_ROLE} to upload logs to CloudWatch" >> $log_filename

Write-Host "AWS/S3 EVENT NOTIFICATION SUCCESSFUL - Below is the summary of important resources"
Write-Host "EVENT S3 SOURCE BUCKET NAME: ${EVENT_S3_SOURCE_BUCKET}"
Write-Host "EVENT S3 SOURCE KEY / FOLDER NAME (with in ${EVENT_S3_SOURCE_BUCKET} bucket) : ${EVENT_S3_SOURCE_KEY}"
Write-Host "LAMBDA FUNCTION SOURCE CODE S3 BUCKET: ${LAMBDA_FUNC_S3_BUCKET}"
Write-Host "LAMBDA FUNCTION SOURCE CODE SOURCE KEY / FOLDER NAME (with in ${LAMBDA_FUNC_S3_BUCKET} bucket) : ${LAMBDA_FUNC_LOC_S3_KEY}"
Write-Host "CONSUMER KEY : ${CONSUMER_KEY_NAME}"
Write-Host "RSA PRIVATE KEY NAME : ${RSA_PRIVATE_KEY_NAME}"
Write-Host "LAMBDA FUNCTION NAME : ${LAMBDA_FUNC_NAME}"
Write-Host "LAMBDA ROLE ARN : ${LAMBDA_ROLE_ARN}"
Write-Host "REGION : ${REGION}"
Write-Host "As a next step, please create event notification on the bucket as per the documentation and then you can create the relevant parent and second level directories (if they don't exist) in the above ${EVENT_S3_SOURCE_BUCKET}/${EVENT_S3_SOURCE_KEY} such that they align with the parent directory in aws/s3 connector and the directory mentioned while UDLO creation"