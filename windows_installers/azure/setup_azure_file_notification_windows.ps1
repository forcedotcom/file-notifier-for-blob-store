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

#edit the input_parameters_azure_windows.txt file with respective environment variables
#on running this script, the window will be redirected to azure portal, just login and close the window, the script will continue its execution to completion
#run this file with command ".\setup_azure_file_notification_windows.ps1 -ConfigFile input_parameters_azure_windows.txt"

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
$RESOURCE_GROUP = $configuration["RESOURCE_GROUP"]
$LOCATION = $configuration["LOCATION"]
$STORAGE_ACCOUNT = $configuration["STORAGE_ACCOUNT"]
$TOPIC_NAME = $configuration["TOPIC_NAME"]
$CONTAINER_NAME = $configuration["CONTAINER_NAME"]
$APP_NAME = $configuration["APP_NAME"]
$SF_USERNAME = $configuration["SF_USERNAME"]
$SF_LOGIN_URL = $configuration["SF_LOGIN_URL"]
$SOURCE_CODE_LOCAL_PATH = $configuration["SOURCE_CODE_LOCAL_PATH"]
$SUBSCRIPTION_NAME = $configuration["SUBSCRIPTION_NAME"]
$KEY_VAULT_NAME = $configuration["KEY_VAULT_NAME"]
$CONSUMER_KEY_VALUE = $configuration["CONSUMER_KEY_VALUE"]
$PEM_FILE_PATH = $configuration["PEM_FILE_PATH"]
$AZURE_SUBSCRIPTION_NAME = $configuration["AZURE_SUBSCRIPTION_NAME"]

# Display configuration values
Write-Host "Environment Variables are set as below"
Write-Host "RESOURCE_GROUP: $RESOURCE_GROUP"
Write-Host "LOCATION: $LOCATION"
Write-Host "STORAGE_ACCOUNT: $STORAGE_ACCOUNT"
Write-Host "CONTAINER_NAME: $CONTAINER_NAME"
Write-Host "SF_USERNAME: $SF_USERNAME"
Write-Host "SOURCE_CODE_LOCAL_PATH: $SOURCE_CODE_LOCAL_PATH"
Write-Host "SF_LOGIN_URL: $SF_LOGIN_URL"
Write-Host "TOPIC_NAME: $TOPIC_NAME"
Write-Host "SUBSCRIPTION_NAME: $SUBSCRIPTION_NAME"
Write-Host "APP_NAME: $APP_NAME"
Write-Host "KEY_VAULT_NAME: $KEY_VAULT_NAME"
Write-Host "CONSUMER_KEY_VALUE: $CONSUMER_KEY_VALUE"
Write-Host "PEM_FILE_PATH: $PEM_FILE_PATH"
Write-Host "AZURE_SUBSCRIPTION_NAME: $AZURE_SUBSCRIPTION_NAME"

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
    $user_input = Read-Host "Have you downloaded the source code for cloud function from https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/cloud_function_zips/azure_function_app.zip into your local machine? (yes/no)"
    if ($user_input -eq "yes") {
        break
    }
    elseif ($user_input -eq "no") {
        Write-Host "Please download source code zip from https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/cloud_function_zips/azure_function_app.zip"
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
    2. Downloading of azure_function_app.zip
    3. Updating parameters in the configuration file input_parameters_azure_windows.txt
    4. renaming keypair.key to keypair.pem (one of the keys generated during pre-requiste step of connected app creation)
    5. azure CLI and powershell installation
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
    $user_input = Read-Host "Do you have 'key vault crypto officer', 'key vault secrets officer' and 'key vault data access administrator' access on your azure subscription? (yes/no):"
    if ($user_input -eq "yes") {
        break
    }
    elseif ($user_input -eq "no") {
        Write-Host "In order to run all the steps of this script, one must have access to 'key vault crypto officer', 'key vault secrets officer' and 'key vault data access administrator' at your azure subscription level, please contact your administrator to add you with these accesses"
        exit
    }
    else{
        Write-Host "Invalid input. Please enter 'yes' or 'no'."
        continue
    }
}

while ($true) {
    $user_input = Read-Host "Running this script will create new resources (if it does not exists) such as resource-group, storage-account, container, function-app, system-topic and event-subscription in azure. Agree to proceed? (yes/no)"
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

# Check if Azure CLI is installed
if (Get-Command az -ErrorAction SilentlyContinue) {
    Write-Host "Azure CLI is installed."
} else {
    Write-Host "Azure CLI is not installed, please install AZURE CLI for windows from https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-windows?tabs=azure-cli"
    exit
}

$currentDateTime = Get-Date -Format "yyyyMMdd_HHmmss"
$log_filename = "logfile_$currentDateTime.txt"

Write-Host "All the azure cloud function installer logs are logged to $log_filename file"

$validation_errors = @()

# Function to add an error to the array
function add_validation_error {
    param (
        [string] $validation_error
    )
  $Script:validation_errors += $validation_error
}

function is_valid_location {
   if ($LOCATION -ne $null) {
        if ($LOCATION) {
            Write-Host "Variable LOCATION has a value"
            "Variable LOCATION has a value" | Out-File -FilePath $log_filename -Append
        } else {
            add_validation_error "Variable LOCATION does not has no value"
            "Variable LOCATION does not have value" | Out-File -FilePath $log_filename -Append
        }
    } else {
        add_validation_error "Variable LOCATION does not exist"
        "Variable LOCATION does not exist" | Out-File -FilePath $log_filename -Append
    }

    # Check if the location is valid
    $validLocations = az account list-locations --query "[].name" --output tsv
    if ($validLocations -contains $LOCATION.ToLower()) {
        Write-Host "The location '$LOCATION' is a valid Azure location"
        "The location '$LOCATION' is a valid Azure location" | Out-File -FilePath $log_filename -Append
    } else {
        add_validation_error "$LOCATION region is invalid, please use a valid region and to get list of available locations, run this 'az account list-locations -o table"

        "$LOCATION region is invalid, please use a valid region and to get list of available locations, run this 'az account list-locations -o table" | Out-File -FilePath $log_filename -Append
    }
}

function is_valid_resource_group_name {

    if ($RESOURCE_GROUP -ne $null) {
        if ($RESOURCE_GROUP) {
            Write-Host "Variable RESOURCE_GROUP has a value"
            "Variable RESOURCE_GROUP has a value" | Out-File -FilePath $log_filename -Append
        } else {
            add_validation_error "Variable RESOURCE_GROUP does not has no value"
            "Variable RESOURCE_GROUP does not have value" | Out-File -FilePath $log_filename -Append
        }
    } else {
        add_validation_error "Variable RESOURCE_GROUP does not exist"
        "Variable RESOURCE_GROUP does not exist" | Out-File -FilePath $log_filename -Append
    }


    # Define the regular expression pattern for a valid resource group name
    $validResourceGroupNamePattern = "^[a-zA-Z0-9_\-\(\)\.]+$"

    # Check if the resource group name is valid
    if ($RESOURCE_GROUP -match $validResourceGroupNamePattern -and $RESOURCE_GROUP.Length -ge 1 -and  $RESOURCE_GROUP.Length -le 90) {
        Write-Host "Resource group ${RESOURCE_GROUP} is valid"
        "Resource group ${RESOURCE_GROUP} is valid" | Out-File -FilePath $log_filename -Append
    } else {
        add_validation_error "Error: Invalid Azure Resource Group Name: ${RESOURCE_GROUP}, Resource group name can only contain alphanumeric characters, hyphens, and underscores"

        "Error: Invalid Azure Resource Group Name: ${RESOURCE_GROUP}, Resource group name can only contain alphanumeric characters, hyphens, and underscores" | Out-File -FilePath $log_filename -Append
    }
}

function is_valid_storage_account_name {

    if ($STORAGE_ACCOUNT -ne $null) {
        if ($STORAGE_ACCOUNT) {
            Write-Host "Variable STORAGE_ACCOUNT has a value"
            "Variable STORAGE_ACCOUNT has a value" | Out-File -FilePath $log_filename -Append
        } else {
            add_validation_error "Variable STORAGE_ACCOUNT does not has no value"
            "Variable STORAGE_ACCOUNT does not have value" | Out-File -FilePath $log_filename -Append
        }
    } else {
        add_validation_error "Variable STORAGE_ACCOUNT does not exist"
        "Variable STORAGE_ACCOUNT does not exist" | Out-File -FilePath $log_filename -Append
    }

    # Define the regular expression pattern for a valid storage account name
    $validStorageAccountNamePattern = "^[a-z0-9]{3,24}$"

    # Check if the storage account name is valid
    if ($STORAGE_ACCOUNT -match $validStorageAccountNamePattern) {
        Write-Host "The storage account name '$STORAGE_ACCOUNT' is valid."
        "The storage account name '$STORAGE_ACCOUNT' is valid." | Out-File -FilePath $log_filename -Append
    } else {
        add_validation_error "Error: Invalid Azure Storage Account Name: ${STORAGE_ACCOUNT}, Storage account name must be between 3 and 24 characters, and can only contain lowercase letters and numbers."

        "Error: Invalid Azure Storage Account Name: ${STORAGE_ACCOUNT}, Storage account name must be between 3 and 24 characters, and can only contain lowercase letters and numbers." | Out-File -FilePath $log_filename -Append
    }
}

function is_valid_storage_container_name {

    if ($CONTAINER_NAME -ne $null) {
        if ($CONTAINER_NAME) {
            Write-Host "Variable CONTAINER_NAME has a value"
            "Variable CONTAINER_NAME has a value" | Out-File -FilePath $log_filename -Append
        } else {
            add_validation_error "Variable CONTAINER_NAME does not has no value"
            "Variable CONTAINER_NAME does not have value" | Out-File -FilePath $log_filename -Append
        }
    } else {
        add_validation_error "CONTAINER_NAME does not exist"
        "Variable CONTAINER_NAME does not exist" | Out-File -FilePath $log_filename -Append
    }


    # Define the regular expression pattern for a valid container name
    $validContainerNamePattern = "^[a-z0-9][a-z0-9\-]{1,61}[a-z0-9]$"

    # Check if the container name is valid
    if ($CONTAINER_NAME -match $validContainerNamePattern) {
        Write-Host "The container name '$CONTAINER_NAME' is valid."
        "The container name '$CONTAINER_NAME' is valid." | Out-File -FilePath $log_filename -Append
    } else {
        add_validation_error "Error: Invalid Azure Storage Container Name: ${CONTAINER_NAME}, Container name must start and end with a letter or number, and can only contain lowercase letters, numbers, and hyphens."

        "Error: Invalid Azure Storage Container Name: ${CONTAINER_NAME}, Container name must start and end with a letter or number, and can only contain lowercase letters, numbers, and hyphens." | Out-File -FilePath $log_filename -Append
    }
}

function is_valid_key_valut_name {

    if ($KEY_VAULT_NAME -ne $null) {
        if ($KEY_VAULT_NAME) {
            Write-Host "Variable KEY_VAULT_NAME has a value"
            "Variable KEY_VAULT_NAME has a value" | Out-File -FilePath $log_filename -Append
        } else {
            add_validation_error "Variable KEY_VAULT_NAME does not has no value"
            "Variable KEY_VAULT_NAME does not have value" | Out-File -FilePath $log_filename -Append
        }
    } else {
        add_validation_error "KEY_VAULT_NAME does not exist"
        "Variable KEY_VAULT_NAME does not exist" | Out-File -FilePath $log_filename -Append
    }

    # Define the regular expression pattern for a valid Key Vault name
    $validKeyVaultNamePattern = "^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$"

    # Check if the Key Vault name is valid
    if ($KEY_VAULT_NAME -match $validKeyVaultNamePattern -and $KEY_VAULT_NAME.Length -ge 3 -and $KEY_VAULT_NAME.Length -le 24) {
        Write-Host "The Key Vault name '$KEY_VAULT_NAME' is valid."
        "The Key Vault name '$KEY_VAULT_NAME' is valid." | Out-File -FilePath $log_filename -Append
    } else {
        add_validation_error "Error: Invalid Azure Key Vault Name: ${KEY_VAULT_NAME}, Key Vault name must be between 3 and 24 characters long and can only contain letters, numbers, and hyphens."

        "Error: Invalid Azure Key Vault Name: ${KEY_VAULT_NAME}, Key Vault name must be between 3 and 24 characters long and can only contain letters, numbers, and hyphens." | Out-File -FilePath $log_filename -Append
    }
}

function is_valid_system_topic_name {

    if ($TOPIC_NAME -ne $null) {
        if ($TOPIC_NAME) {
            Write-Host "Variable TOPIC_NAME has a value"
            "Variable TOPIC_NAME has a value" | Out-File -FilePath $log_filename -Append
        } else {
            add_validation_error "Variable TOPIC_NAME does not has no value"
            "Variable TOPIC_NAME does not have value" | Out-File -FilePath $log_filename -Append
        }
    } else {
        add_validation_error "TOPIC_NAME does not exist"
        "Variable TOPIC_NAME does not exist" | Out-File -FilePath $log_filename -Append
    }

    # Define the regular expression pattern for a valid system topic name
    $validSystemTopicNamePattern = "^[a-zA-Z0-9][a-zA-Z0-9-_.]{0,258}[a-zA-Z0-9]$"

    # Check if the system topic name is valid
    if ($TOPIC_NAME -match $validSystemTopicNamePattern -and $TOPIC_NAME.Length -ge 1 -and $TOPIC_NAME.Length -le 260) {
        Write-Host "The system topic name '$TOPIC_NAME' is valid."
        "The system topic name '$TOPIC_NAME' is valid." | Out-File -FilePath $log_filename -Append
    } else {
        add_validation_error "Error: Invalid Azure System Topic Name: ${TOPIC_NAME}, System Topic name must be between 3 and 24 characters long and can only contain letters, numbers, and hyphens."

        "Error: Invalid Azure System Topic Name: ${TOPIC_NAME}, System Topic name must be between 3 and 258 characters long and can only contain letters, numbers, and hyphens." | Out-File -FilePath $log_filename -Append
    }
}

function is_valid_functionapp_name {

    if ($APP_NAME -ne $null) {
        if ($APP_NAME) {
            Write-Host "Variable APP_NAME has a value"
            "Variable APP_NAME has a value" | Out-File -FilePath $log_filename -Append
        } else {
            add_validation_error "Variable APP_NAME does not has no value"
            "Variable APP_NAME does not have value" | Out-File -FilePath $log_filename -Append
        }
    } else {
        add_validation_error "APP_NAME does not exist"
        "Variable APP_NAME does not exist" | Out-File -FilePath $log_filename -Append
    }

    # Define the regular expression pattern for a valid Function App name
    $validFunctionAppNamePattern = "^[a-zA-Z][a-zA-Z0-9-]{0,58}[a-zA-Z0-9]$"

    # Check if the Function App name is valid
    if ($APP_NAME -match $validFunctionAppNamePattern -and $APP_NAME.Length -ge 2 -and $APP_NAME.Length -le 60) {
        Write-Host "The Function App name '$APP_NAME' is valid."
        "The Function App name '$APP_NAME' is valid." | Out-File -FilePath $log_filename -Append
    } else {
        add_validation_error "Error: Invalid Azure Function App Name: ${APP_NAME}, Function App name must be between 2 and 60 characters long and can only contain letters, numbers, and hyphens."

        "Error: Invalid Azure Function App Name: ${APP_NAME}, Function App name must be between 2 and 60 characters long and can only contain letters, numbers, and hyphens." | Out-File -FilePath $log_filename -Append
    }
}

function is_valid_subscriber_name {

    if ($SUBSCRIPTION_NAME -ne $null) {
        if ($SUBSCRIPTION_NAME) {
            Write-Host "Variable SUBSCRIPTION_NAME has a value"
            "Variable SUBSCRIPTION_NAME has a value" | Out-File -FilePath $log_filename -Append
        } else {
            add_validation_error "Variable SUBSCRIPTION_NAME does not has no value"
            "Variable SUBSCRIPTION_NAME does not have value" | Out-File -FilePath $log_filename -Append
        }
    } else {
        add_validation_error "SUBSCRIPTION_NAME does not exist"
        "Variable SUBSCRIPTION_NAME does not exist" | Out-File -FilePath $log_filename -Append
    }


   # Define the regular expression pattern for a valid system topic subscriber name
    $validSubscriberNamePattern = "^[a-zA-Z0-9_-]+$"

    # Check if the system topic subscriber name is valid
    if ($SUBSCRIPTION_NAME -match $validSubscriberNamePattern -and $SUBSCRIPTION_NAME.Length -ge 1 -and $SUBSCRIPTION_NAME.Length -le 50) {
        Write-Host "The system topic subscriber name '$SUBSCRIPTION_NAME' is valid."
        "The system topic subscriber name '$SUBSCRIPTION_NAME' is valid." | Out-File -FilePath $log_filename -Append
    } else {
        add_validation_error "Error: Invalid Azure Subscriber Name: ${SUBSCRIPTION_NAME}, Topic Subscriber name must be between 1 and 50 characters long and can only contain letters, numbers, and hyphens."

        "Error: Invalid Azure Subscriber Name: ${SUBSCRIPTION_NAME}, Topic Subscriber name must be between 1 and 50 characters long and can only contain letters, numbers, and hyphens." | Out-File -FilePath $log_filename -Append
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

is_valid_resource_group_name
is_valid_storage_account_name
is_valid_storage_container_name
is_valid_system_topic_name
is_valid_functionapp_name
is_valid_key_valut_name
is_valid_subscriber_name
is_valid_source_code_local_path
is_valid_pem_file_path

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
    Write-Host "NOTE: Please check descriptions of each variable https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/installers/azure/input_parameters_azure.conf"

    "NOTE: Please check descriptions of each variable in https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/installers/azure/input_parameters_azure.conf" | Out-File -FilePath $log_filename -Append

    exit
}

az config set core.allow_broker=true
az account clear
az login

#set azure subscription
Set-AzContext -SubscriptionId $AZURE_SUBSCRIPTION_NAME

is_valid_location

Write-Host "Step 1/14 : Successfully logged into Azure"
"Step 1/14 : Successfully logged into Azure" | Out-File -FilePath $log_filename -Append

# Check if the resource group exists using Azure CLI
$resourceGroupExists = az group show --name $RESOURCE_GROUP --query id --output tsv 2>$null

# If the resource group does not exist, create it
if (-not $resourceGroupExists) {
    # Create the resource group
    $resourceGroupCreateOutput = az group create --name $RESOURCE_GROUP --location $LOCATION

    if ($resourceGroupCreateOutput) {
        Write-Host "Step 2/14 : Successfully created resource group ${RESOURCE_GROUP}"
        "Step 2/14 : Successfully created resource group ${RESOURCE_GROUP}" | Out-File -FilePath $log_filename -Append
    } else {
        Write-Host "Step 2/14 : Failed to create resource group ${RESOURCE_GROUP}"
        "Step 2/14 : Failed to create resource group ${RESOURCE_GROUP}" | Out-File -FilePath $log_filename -Append
        exit
    }
 } else {
    Write-Host "Step 2/14 : Resource Group with name ${RESOURCE_GROUP} exists and skipping the creation of resource group"
    "Step 2/14 : Resource Group with name ${RESOURCE_GROUP} exists and skipping the creation of resource group" | Out-File -FilePath $log_filename -Append
}

# Check if the storage account exists using Azure CLI
$storageAccountExists = az storage account show --name $STORAGE_ACCOUNT --resource-group $RESOURCE_GROUP --query name -o tsv 2>$null

# If the storage account does not exist, create it
if (-not $storageAccountExists) {
    # Create the storage account and capture the output
    $storageAccountCreateOutput = az storage account create --name $STORAGE_ACCOUNT --resource-group $RESOURCE_GROUP --location $LOCATION --sku Standard_LRS

    # Check if the output contains information about the created storage account
    if ($storageAccountCreateOutput) {
        Write-Host "Step 3/14 : Successfully created storage account ${STORAGE_ACCOUNT}"
        "Step 3/14 : Successfully created storage account ${STORAGE_ACCOUNT}" | Out-File -FilePath $log_filename -Append
    } else {
         Write-Host "Step 3/14 : Failed to create storage account ${STORAGE_ACCOUNT}"
         "Step 3/14 : Failed to create storage account ${STORAGE_ACCOUNT}" | Out-File -FilePath $log_filename -Append
         exit
    }
} else {
        Write-Host "Step 3/14 : Storage Account with name ${STORAGE_ACCOUNT} exists and skipping the creation of storage account"
        "Step 3/14 : Storage Account with name ${STORAGE_ACCOUNT} exists and skipping the creation of storage account" | Out-File -FilePath $log_filename -Append
}

$conn=$(az storage account show-connection-string --resource-group $RESOURCE_GROUP --name $STORAGE_ACCOUNT --query connectionString -o tsv)

# Check if the container exists using Azure CLI
$containerExists = az storage container exists --account-name $STORAGE_ACCOUNT --name $CONTAINER_NAME --query exists -o tsv 2>$null

# If the container does not exist, create it
if ($containerExists -ne "true") {
    # Create the container
    $containerCreateOutput = az storage container create --name $CONTAINER_NAME --account-name $STORAGE_ACCOUNT --connection-string $conn

    # Check if the output contains information about the created container
    if ($containerCreateOutput) {
         Write-Host "Step 4/14 : Successfully created container ${CONTAINER_NAME}"
         "Step 4/14 : Successfully created container ${CONTAINER_NAME}" | Out-File -FilePath $log_filename -Append
    } else {
        Write-Host "Step 4/14 : Failed to create container ${CONTAINER_NAME}"
        "Step 4/14 : Failed to create container ${CONTAINER_NAME}" | Out-File -FilePath $log_filename -Append
        exit
    }
} else {
    Write-Host "Step 4/14 : Container with name ${CONTAINER_NAME} exists, skipping the creation of container"
    "Step 4/14 : Container with name ${CONTAINER_NAME} exists, skipping the creation of container" | Out-File -FilePath $log_filename -Append
}

az provider register --namespace Microsoft.EventGrid

Write-Host "Step 5/14 : Successfully registered the namespace"
"Step 5/14 : Successfully registered the namespace" | Out-File -FilePath $log_filename -Append

az provider show --namespace Microsoft.EventGrid --query "registrationState"

$subscriptionId="$(az account show --query id -o tsv)"

# Check if the system topic exists using Azure CLI
$systemTopicExists = az eventgrid system-topic show --name $TOPIC_NAME --resource-group $RESOURCE_GROUP --query name -o tsv 2>$null

# If the system topic does not exist, create it
if (-not $systemTopicExists) {

    $EXISTING_SYSTEM_TOPIC=$(az eventgrid system-topic list --subscription $subscriptionId --resource-group $RESOURCE_GROUP --query "[].source" --output json)

    if($EXISTING_SYSTEM_TOPIC -eq "")
    {
        Write-Host "Step 6/14 : There already exists one system topic for the combination of resource group ${RESOURCE_GROUP} and storage account ${STORAGE_ACCOUNT}, Only one system topic is allowed per resource group and storage account combination, please choose different resource group or storage account"

        "Step 6/14 : There already exists one system topic for the combination of resource group ${RESOURCE_GROUP} and storage account ${STORAGE_ACCOUNT}, Only one system topic is allowed per resource group and storage account combination, please choose different resource group or storage account" | Out-File -FilePath $log_filename -Append
        exit
    }

    # Create the system topic and capture the output
    $systemTopicCreateOutput = az eventgrid system-topic create --name $TOPIC_NAME --location $LOCATION --resource-group $RESOURCE_GROUP --source /subscriptions/${subscriptionId}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Storage/storageAccounts/${STORAGE_ACCOUNT} --topic-type microsoft.storage.storageaccounts

    # Check if the output contains information about the created system topic
    if ($systemTopicCreateOutput) {
        Write-Host "Step 6/14 : Successfully created system-topic ${TOPIC_NAME}"
        "Step 6/14 : Successfully created system-topic ${TOPIC_NAME}" | Out-File -FilePath $log_filename -Append
    } else {
        Write-Host "Step 6/14 : Failed to create system-topic ${TOPIC_NAME}"
        "Step 6/14 : Failed to create system-topic ${TOPIC_NAME}" | Out-File -FilePath $log_filename -Append
        exit
    }
} else {
    Write-Host "Step 6/14 : System topic with name ${TOPIC_NAME} already exists, skipping the creation of ${TOPIC_NAME} topic"
    "Step 6/14 : System topic with name ${TOPIC_NAME} already exists, skipping the creation of ${TOPIC_NAME} topic" | Out-File -FilePath $log_filename -Append
}


# Check if the function app exists using Azure CLI
$functionAppExists = az functionapp show --name $APP_NAME --resource-group $RESOURCE_GROUP --query name -o tsv 2>$null

# If the function app does not exist, create it
if (-not $functionAppExists) {
    # Create the function app and capture the output
    $functionAppCreateOutput = az functionapp create --resource-group ${RESOURCE_GROUP} --consumption-plan-location ${LOCATION} --runtime python --runtime-version 3.9 --functions-version 4 --name ${APP_NAME} --os-type linux --assign-identity '[system]' --storage-account ${STORAGE_ACCOUNT}

    # Check if the output contains information about the created function app
    if ($functionAppCreateOutput) {
        Write-Host "Step 7/14 : Successfully created function app ${APP_NAME}"
        "Step 7/14 : Successfully created function app ${APP_NAME}" | Out-File -FilePath $log_filename -Append
    } else {
        Write-Host "Step 7/14 : Failed create function app ${APP_NAME}"
        "Step 7/14 : Failed create function app ${APP_NAME}" | Out-File -FilePath $log_filename -Append
        exit
    }
} else {
    Write-Host "Step 7/14 : App with name ${APP_NAME} exists and skipping the creation of ${APP_NAME} app"
    "Step 7/14 : App with name ${APP_NAME} exists and skipping the creation of ${APP_NAME} app" | Out-File -FilePath $log_filename -Append
}

# Check if the Key Vault exists using Azure CLI
$keyVaultExists = az keyvault show --name $KEY_VAULT_NAME --resource-group $RESOURCE_GROUP --query name -o tsv 2>$null

# If the Key Vault does not exist, create it
if (-not $keyVaultExists) {
    # Create the Key Vault and capture the output
    $keyVaultCreateOutput = az keyvault create --name $KEY_VAULT_NAME --resource-group $RESOURCE_GROUP --location $LOCATION

    # Check if the output contains information about the created Key Vault
    if ($keyVaultCreateOutput) {
        Write-Host "Step 8/14 : Successfully created keyVault ${KEY_VAULT_NAME}"
        "Step 8/14 : Successfully created keyVault ${KEY_VAULT_NAME}" | Out-File -FilePath $log_filename -Append
    } else {
        Write-Host "Step 8/14 : Failed to create keyVault ${KEY_VAULT_NAME}"
        "Step 8/14 : Failed to create keyVault ${KEY_VAULT_NAME}" | Out-File -FilePath $log_filename -Append
    }
} else {
    Write-Host "Step 8/14 : KeyVault with name ${KEY_VAULT_NAME} exists, skipping the creation of KeyVault"
    "Step 8/14 : KeyVault with name ${KEY_VAULT_NAME} exists, skipping the creation of KeyVault" | Out-File -FilePath $log_filename -Append
}

# Check if the rsa private key exists in the Key Vault
$rsaKeyExists = az keyvault key show --vault-name $KEY_VAULT_NAME --name "RSA-PRIVATE-KEY" --query name -o tsv 2>$null

# If the rsa private key does not exist, import it
if (-not $rsaKeyExists) {
    # Import the public key from the PEM file into Azure Key Vault
    $rsaKeyCreateOutput = az keyvault key import --vault-name $KEY_VAULT_NAME --name "RSA-PRIVATE-KEY" --pem-file $PEM_FILE_PATH

    # Check if the output contains information about the imported file
    if ($rsaKeyCreateOutput) {
        Write-Host "Step 9/14 : Successfully created secret with name RSA-PRIVATE-KEY under KeyVault ${KEY_VAULT_NAME}"
        "Step 9/14 : Successfully created secret with name RSA-PRIVATE-KEY under KeyVault ${KEY_VAULT_NAME}" | Out-File -FilePath $log_filename -Append
    } else {
        Write-Host "Step 9/14 : Failed to create secret with name RSA-PRIVATE-KEY under KeyVault ${KEY_VAULT_NAME}"
        "Step 9/14 : Failed to create secret with name RSA-PRIVATE-KEY under KeyVault ${KEY_VAULT_NAME}" | Out-File -FilePath $log_filename -Append
        exit
    }
} else {
    Write-Host "Step 9/14 : Key with name RSA-PRIVATE-KEY exists under KeyVault ${KEY_VAULT_NAME}, skipping the creation of RSA-PRIVATE-KEY"
    "Step 9/14 : Key with name RSA-PRIVATE-KEY exists under KeyVault ${KEY_VAULT_NAME}, skipping the creation of RSA-PRIVATE-KEY" | Out-File -FilePath $log_filename -Append
}

# Check if the consumer key exists in the Key Vault
$consumerKeyExists = az keyvault key show --vault-name $KEY_VAULT_NAME --name "CONSUMER-KEY" --query name -o tsv 2>$null

# If the consumer key does not exist, create it
if (-not $consumerKeyExists) {
    $consumerKeyCreateOutput = az keyvault secret set --vault-name $KEY_VAULT_NAME --name "CONSUMER-KEY" --value $CONSUMER_KEY_VALUE

    # Check if the output contains information about the imported file
    if ($consumerKeyCreateOutput) {
        Write-Host "Step 10/14 : Successfully created secret with name CONSUMER-KEY under KeyVault ${KEY_VAULT_NAME}"
        "Step 9/14 : Successfully created secret with name CONSUMER-KEY under KeyVault ${KEY_VAULT_NAME}" | Out-File -FilePath $log_filename -Append
    } else {
        Write-Host "Step 10/14 : Failed to create secret with name CONSUMER-KEY under KeyVault ${KEY_VAULT_NAME}"
        "Step 10/14 : Failed to create secret with name CONSUMER-KEY under KeyVault ${KEY_VAULT_NAME}" | Out-File -FilePath $log_filename -Append
        exit
    }
} else {
    Write-Host "Step 10/14 : Key with name CONSUMER-KEY exists under KeyVault ${KEY_VAULT_NAME}, skipping the creation of RSA-PRIVATE-KEY"
    "Step 10/14 : Key with name CONSUMER-KEY exists under KeyVault ${KEY_VAULT_NAME}, skipping the creation of RSA-PRIVATE-KEY" | Out-File -FilePath $log_filename -Append
}

az functionapp config appsettings set --name $APP_NAME --resource-group ${RESOURCE_GROUP} --settings SF_LOGIN_URL=$SF_LOGIN_URL SF_USERNAME=$SF_USERNAME KEY_VAULT_NAME=$KEY_VAULT_NAME

Write-Host "Step 11/14 : Successfully set config settings to function app with name ${APP_NAME}"
"Step 11/14 : Successfully set config settings to function app with name ${APP_NAME}" | Out-File -FilePath $log_filename -Append

az functionapp deployment source config-zip --resource-group $RESOURCE_GROUP --name $APP_NAME --src $SOURCE_CODE_LOCAL_PATH --build-remote true --verbose

Write-Host  "Step 12/14 : Successfully deplopyed function app with name ${APP_NAME}"
"Step 12/14 : Successfully deplopyed function app with name ${APP_NAME}" | Out-File -FilePath $log_filename -Append

appPrincipalIdentity="$(az functionapp show --name $APP_NAME --resource-group $RESOURCE_GROUP --query identity.principalId -o tsv)"

$roleDefinitionCryptoId = (Get-AzRoleDefinition -Name "Key Vault Crypto Officer").Id
$roleDefinitionSecretsId = (Get-AzRoleDefinition -Name "Key Vault Secrets Officer").Id

New-AzRoleAssignment -ObjectId $appPrincipalIdentity -RoleDefinitionId $roleDefinitionCryptoId -Scope subscriptions/${subscriptionId}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.KeyVault/vaults/${KEY_VAULT_NAME}
New-AzRoleAssignment -ObjectId $appPrincipalIdentity -RoleDefinitionId $roleDefinitionSecretsId -Scope subscriptions/${subscriptionId}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.KeyVault/vaults/${KEY_VAULT_NAME}

Write-Host  "Step 13/14 : Successfully attached key vault Crypto and Secrets Officer role to key vault ${KEY_VAULT_NAME}"
"Step 13/14 : Successfully attached key vault Crypto and Secrets Officer role to key vault ${KEY_VAULT_NAME}" | Out-File -FilePath $log_filename -Append

# Check if the event subscription exists using Azure CLI
$eventSubscriptionExists = az eventgrid system-topic event-subscription show --name $SUBSCRIPTION_NAME --resource-group $RESOURCE_GROUP --system-topic-name $TOPIC_NAME --query name -o tsv 2>$null

# If the event subscription does not exist, create it
if (-not $eventSubscriptionExists) {
    # Create the event subscription and capture the output

    $eventSubscriptionCreateOutput = New-AzEventGridSubscription -ResourceGroup ${RESOURCE_GROUP} -TopicName ${TOPIC_NAME} -Endpoint subscriptions/${subscriptionId}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Web/sites/${APP_NAME}/functions/eventGridTrigger -EventSubscriptionName ${SUBSCRIPTION_NAME}

    # Check if the output contains information about the created event subscription
    if ($eventSubscriptionCreateOutput) {
        Write-Host "Step 14/14 : Successfully created subscription ${SUBSCRIPTION_NAME} to topic ${TOPIC_NAME}"
        "Step 14/14 : Successfully created subscription ${SUBSCRIPTION_NAME} to topic ${TOPIC_NAME}" | Out-File -FilePath $log_filename -Append
    } else {
        Write-Host "Step 14/14 : Faield to create subscription ${SUBSCRIPTION_NAME} to topic ${TOPIC_NAME}"
        "Step 14/14 : Faield to create subscription ${SUBSCRIPTION_NAME} to topic ${TOPIC_NAME}" | Out-File -FilePath $log_filename -Append
    }

} else {
    Write-Host "Step 14/14 : subscriptions with name ${SUBSCRIPTION_NAME} to system-topic ${TOPIC_NAME} already exists, skipping the subscription of ${SUBSCRIPTION_NAME} to ${TOPIC_NAME} topic"

    "Step 14/14 : subscriptions with name ${SUBSCRIPTION_NAME} to system-topic ${TOPIC_NAME} already exists, skipping the subscription of ${SUBSCRIPTION_NAME} to ${TOPIC_NAME} topic" | Out-File -FilePath $log_filename -Append
    exit
}

Write-Host "All the azure cloud function installer logs are logged to ${log_filename} file"

Write-Host "AZURE EVENT NOTIFICATION SUCCESSFUL - Below is the summary of important resources"
Write-Host "RESOURCE GROUP NAME: ${RESOURCE_GROUP}"
Write-Host "STORAGE ACCOUNT NAME : ${STORAGE_ACCOUNT}"
Write-Host "CONTAINER NAME : ${CONTAINER_NAME}"
Write-Host "KEY VAULT NAME : ${KEY_VAULT_NAME}"
Write-Host "FUNCTION APP NAME : ${APP_NAME}"
Write-Host "SYSTEM TOPIC NAME : ${TOPIC_NAME}"
Write-Host "SUBSCRIPTION_NAME : ${SUBSCRIPTION_NAME}"
Write-Host "REGION / LOCATION : ${LOCATION}"
Write-Host "As a next step, you can create the relevant parent and second level directories (if they don't exist) in the above ${CONTAINER_NAME} such that they align with the parent directory in Azure connector and the directory mentioned while UDLO creation"