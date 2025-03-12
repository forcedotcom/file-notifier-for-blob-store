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
#on running this script, the window will be redirected to azure portal, just login and close the window, the script will continue its execution to completion
#run "chmod +x setup_azure_file_notification.sh"
#run this file with command "./setup_azure_file_notification.sh <input_parameters_azure.conf>"
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
  echo "Have you downloaded the source code for cloud function from https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/cloud_function_zips/azure_function_app.zip into your local machine? (yes/no):"
  read user_input

  if [ "$user_input" == "yes" ]; then
    break
  elif [ "$user_input" == "no" ]; then
    echo "Please download source code zip from https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/cloud_function_zips/azure_function_app.zip"
    exit
  else
    echo "Invalid input. Please enter 'yes' or 'no'."
  fi
done

while true; do
  echo "Do you have 'key vault crypto officer', 'key vault secrets officer' and 'key vault data access administrator' access on your azure subscription? (yes/no):"
  read user_input

  if [ "$user_input" == "yes" ]; then
    break
  elif [ "$user_input" == "no" ]; then
    echo "In order to run all the steps of this script, one must have access to 'key vault crypto officer', 'key vault secrets officer' and 'key vault data access administrator' at your azure subscription level, please contact your administrator to add you with these accesses"
    exit
  else
    echo "Invalid input. Please enter 'yes' or 'no'."
  fi
done

while true; do
  echo "Running this script will create new resources (if it does not exists) such as resource-group, storage-account, container, function-app, system-topic and event-subscription in azure. Agree to proceed? (yes/no):"
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

function install_azure_cli {
  #Check the operating system and perform actions accordingly
  if [[ "$OSTYPE" = "linux-gnu"* ]]; then
    echo "Choose the distribution of Linux : ubuntu/Redhat/Azure-Linux? :"
    read linux_distribution_type

    if [ "$linux_distribution_type" == "ubuntu" ]; then
      curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

    elif [ "$linux_distribution_type" == "Redhat" ]; then
      sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
      echo "Choose the version of Redhat (RHEL) : 7/8/9? : (os version information can be viewed by running 'cat /etc/os-release' from another terminal)"
      read redhat_version

      if [ "$redhat_version" == "7" ]; then
          echo -e "[azure-cli] name=Azure CLI baseurl=https://packages.microsoft.com/yumrepos/azure-cli enabled=1 gpgcheck=1 gpgkey=https://packages.microsoft.com/keys/microsoft.asc" | sudo tee /etc/yum.repos.d/azure-cli.repo
          sudo dnf install azure-cli

      elif [ "$redhat_version" == "8" ]; then
        sudo dnf install -y https://packages.microsoft.com/config/rhel/8/packages-microsoft-prod.rpm
        sudo dnf install azure-cli

      elif [ "$redhat_version" == "9" ]; then
        sudo dnf install -y https://packages.microsoft.com/config/rhel/9.0/packages-microsoft-prod.rpm
        sudo dnf install azure-cli

      else
        echo "Invalid input, currently we support only 7,8 and 9 versions of redhat linux OS"
        exit
      fi

    elif [ "$linux_distribution_type" == "Azure-Linux" ]; then
        sudo tdnf install ca-certificates
        sudo tdnf install azure-cli

    else
      echo "Invalid input, currently we support only ubuntu, RedHat and Azure-Linux distributions of linux only"
      exit
    fi
  elif [ "$OSTYPE" = "darwin"* ]; then
    brew update && brew install azure-cli
    brew tap azure/functions
    brew install azure-functions-core-tools@4
    brew link --overwrite azure-functions-core-tools@4

   elif [ "$OSTYPE" = "cygwin*" || "$OSTYPE" = "msys"* ]; then
    echo "Download the installer from https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-windows?tabs=azure-cli and follow the installation instructions."
    echo "After the installation, you may need to restart your terminal or command prompt to make the az command available."
    echo "Once installed, you can verify the installation by running: az --version"
    echo "Download the installer from https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-windows?tabs=azure-cli and follow the installation instructions." >> $log_filename
    echo "After the installation, you may need to restart your terminal or command prompt to make the az command available." >> $log_filename
    echo "Once installed, you can verify the installation by running: az --version" >> $log_filename
    exit
  fi

  if command -v az &> /dev/null; then
    echo "azure CLI has been successfully installed."
    echo "azure CLI has been successfully installed." >> $log_filename
  else
    echo "Error: azure CLI installation failed, please install azure cli from https://learn.microsoft.com/en-us/cli/azure/install-azure-cli and then re-run this script post installation"
    echo "Error: azure CLI installation failed, please install azure cli from https://learn.microsoft.com/en-us/cli/azure/install-azure-cli and then re-run this script post installation" >> $log_filename
    exit
  fi
}

current_time=$(date +"%Y-%m-%d_%H:%M:%S")

log_filename="log_${current_time}.txt"

echo "All the azure cloud function installer logs are logged to ${log_filename} file"

#this is the make sure that in case of new installation we have to perform az login in order to set it up
IS_AZURE_CLI_NEWLY_INSTALLED="false"

if command -v az &> /dev/null; then
  echo "Azure CLI is already installed, skipping the installation"
  echo "Azure CLI is already installed, skipping the installation" >> $log_filename
else
  install_azure_cli
  az config set core.allow_broker=true
  az account clear
  az login >> $log_filename
  IS_AZURE_CLI_NEWLY_INSTALLED="true"
fi

# Check if the config file is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <config_file>"
  exit 1
fi

config_file=$1
echo "config file is ${config_file}"

# Check if the file exists
if [ ! -f "$config_file" ]; then
  echo "Error: File not found - $config_file"
  echo "Error: File not found - $config_file" >> $log_filename
  exit 1
fi

source $config_file

# Array to store validation errors
validation_errors=()

# Function to add an error to the array
add_validation_error() {
  validation_errors+=("$1")
}

#validation for valid location
function is_valid_location {
  if [ -z "${LOCATION}" ]; then
    echo "Error: Location is missing/empty. Please provide a valid location."
    echo "Error: Location is missing/empty. Please provide a valid location." >> $log_filename
    exit
  elif az account list-locations | grep -q $LOCATION ; then
    echo "${LOCATION} is a valid region"
    echo "${LOCATION} is a valid region" >> $log_filename
  else
    echo "${LOCATION} region is invalid, please use a valid region and to get list of available locations, run this 'az account list-locations -o table'";
    echo "${LOCATION} region is invalid, please use a valid region and to get list of available locations, run this 'az account list-locations -o table'" >> $log_filename
    exit
  fi
}

function is_valid_resource_group_name {
    local regex="^[a-zA-Z0-9_-]{1,90}$"

    if [ -z "$RESOURCE_GROUP" ]; then
        add_validation_error "Error: Resource Group name is missing/empty. Please provide a valid Resource Group name."
    elif [[ "$RESOURCE_GROUP" =~ $regex ]]; then
        echo "resource group ${RESOURCE_GROUP} is valid"
        echo "resource group ${RESOURCE_GROUP} is valid" >> $log_filename
    else
        add_validation_error "Error: Invalid Azure Resource Group Name: ${RESOURCE_GROUP}, Resource group name can only contain alphanumeric characters, hyphens, and underscores."
    fi
}

function is_valid_storage_account_name {
    local regex="^[a-z0-9]{3,24}$"

    if [ -z "$STORAGE_ACCOUNT" ]; then
        add_validation_error "Error: Storage Account name is missing/empty. Please provide a valid Storage Account name."
    elif [[ "$STORAGE_ACCOUNT" =~ $regex ]]; then
      echo "storage account ${STORAGE_ACCOUNT} is valid"
      echo "storage account ${STORAGE_ACCOUNT} is valid" >> $log_filename
    else
        add_validation_error "Error: Invalid Azure Storage Account Name: ${STORAGE_ACCOUNT}, Storage account name must be between 3 and 24 characters, and can only contain lowercase letters and numbers."
    fi
}

function is_valid_storage_container_name {
    local regex="^[a-z0-9][a-z0-9-]{2,62}$"

    if [ -z "$CONTAINER_NAME" ]; then
        add_validation_error "Error: Storage Container name is missing/empty. Please provide a valid Storage Container name."
    elif [[ "$CONTAINER_NAME" =~ $regex ]]; then
        echo "container name ${CONTAINER_NAME} is valid"
        echo "container name ${CONTAINER_NAME} is valid" >> $log_filename
    else
        add_validation_error "Error: Invalid Azure Storage Container Name: ${CONTAINER_NAME}, Container name must start and end with a letter or number, and can only contain lowercase letters, numbers, and hyphens."
    fi
}

function is_valid_key_valut_name {
    local regex="^[a-zA-Z0-9-]{3,24}$"

    if [ -z "$KEY_VAULT_NAME" ]; then
        add_validation_error "Error: key vault name is missing/empty. Please provide a valid key vault name."
    elif [[ "$KEY_VAULT_NAME" =~ $regex ]]; then
        echo "keyvalut name ${KEY_VALUT_NAME} is valid"
        echo "keyvalut name ${KEY_VALUT_NAME} is valid" >> $log_filename
    else
        add_validation_error "Error: Invalid Azure Key Vault Name: ${KEY_VAULT_NAME}, Key Vault name must be between 3 and 24 characters long and can only contain letters, numbers, and hyphens."
    fi
}

function is_valid_system_topic_name {
    local regex="^[a-zA-Z0-9-]{3,24}$"

    if [ -z "$TOPIC_NAME" ]; then
        add_validation_error "Error: System topic name is missing/empty. Please provide a valid system topic name."
    elif [[ "$TOPIC_NAME" =~ $regex ]]; then
        echo "system topic name ${TOPIC_NAME} is valid"
        echo "system topic name ${TOPIC_NAME} is valid" >> $log_filename
    else
        add_validation_error "Error: Invalid Azure System Topic Name: ${TOPIC_NAME}, System Topic name must be between 3 and 24 characters long and can only contain letters, numbers, and hyphens."
    fi
}

function is_valid_functionapp_name {
    local regex="^[a-zA-Z0-9-]{2,60}$"

    if [ -z "$APP_NAME" ]; then
      add_validation_error "Error: Function app name is missing/empty. Please provide a valid function app name."
    elif [[ "$APP_NAME" =~ $regex ]]; then
        echo "function app name ${APP_NAME} is valid"
        echo "function app name ${APP_NAME} is valid" >> $log_filename
    else
        add_validation_error "Error: Invalid Azure Function App Name: ${APP_NAME}, Function App name must be between 2 and 60 characters long and can only contain letters, numbers, and hyphens."
    fi
}

function is_valid_subscriber_name {
    local regex="^[a-zA-Z0-9-]{1,50}$"

    if [ -z "$SUBSCRIPTION_NAME" ]; then
      add_validation_error "Error: Subscriber name is missing/empty. Please provide a valid subscriber name."
    elif [[ "$SUBSCRIPTION_NAME" =~ $regex ]]; then
        echo "subscription name ${SUBSCRIPTION_NAME} is valid"
        echo "subscription name ${SUBSCRIPTION_NAME} is valid" >> $log_filename
    else
        add_validation_error "Error: Invalid Azure Subscriber Name: ${SUBSCRIPTION_NAME}, Topic Subscriber name must be between 1 and 50 characters long and can only contain letters, numbers, and hyphens."
    fi
}

#validate the existance of local source code path for cloud function
function is_valid_source_code_local_path {
  if [ -z "$SOURCE_CODE_LOCAL_PATH" ]; then
    add_validation_error "Error: Source code local path is missing/empty. Please provide a valid Source code local path and source code zip can be downloaded from https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/cloud_function_zips/azure_function_app.zip"
  elif [ -f $SOURCE_CODE_LOCAL_PATH ]; then
    echo "source code local path ${SOURCE_CODE_LOCAL_PATH} exists"
    echo "source code local path ${SOURCE_CODE_LOCAL_PATH} exists" >> $log_filename

    local filename=$(basename "$SOURCE_CODE_LOCAL_PATH")

    if [[ "$filename" == *.zip ]]; then
      echo "${SOURCE_CODE_LOCAL_PATH} has a valid file of type .zip"
      echo "${SOURCE_CODE_LOCAL_PATH} has a valid file of type .zip" >> $log_filename
    else
      add_validation_error "Error: Please include file with .zip extension for SOURCE_CODE_LOCAL_PATH"
    fi

  else
    add_validation_error "Error: Source code local path ${SOURCE_CODE_LOCAL_PATH} for cloud function deployment does not exist or is invalid, please validate your input config, source code zip can be downloaded from https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/cloud_function_zips/azure_function_app.zip"
fi
}

function is_valid_pem_file_path {
  #validate the existance of local pem file path for adding secrete keys
  if [ -z "$PEM_FILE_PATH" ]; then
    add_validation_error "Error: PEM_FILE_PATH or keypair.pem file path is missing/empty. Please provide a valid .pem file path"
  elif [ -f $PEM_FILE_PATH ]; then
    echo "pem file path ${PEM_FILE_PATH} exists"
    echo "pem file path ${PEM_FILE_PATH} exists" >> $log_filename
  else
    add_validation_error "Error: PEM_FILE_PATH - ${PEM_FILE_PATH} for creating RSA_PRIVATE_KEY does not exist or is invalid or is not of .pem type, please create it using openssl commands"
  fi

  # Extract file name without path and check if the file name ends with ".pem"
  local filename=$(basename "$PEM_FILE_PATH")

  if [[ "$filename" == *.pem ]]; then
    echo "pem file path has valid pem file of type pem"
    echo "pem file path has valid pem file of type pem" >> $log_filename
  else
    add_validation_error "Error: Please include file with .pem extension for PEM_FILE_PATH"
  fi
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

# Print all the validation errors
if [ ${#validation_errors[@]} -gt 0 ]; then
  echo "There are validation errors as below:"
  echo "There are validation errors as below:" >> $log_filename
  for validation_error in "${validation_errors[@]}"; do
    echo "$validation_error"
    echo "$validation_error" >> $log_filename
  done
  echo "NOTE: Please check descriptions of each variable in https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/installers/azure/input_parameters_azure.conf"
  echo "NOTE: Please check descriptions of each variable in https://github.com/forcedotcom/file-notifier-for-blob-store/blob/main/installers/azure/input_parameters_azure.conf" >> $log_filename
  exit
else
  echo "No validation errors."
  echo "No validation errors." >> $log_filename
fi

if [ "${IS_AZURE_CLI_NEWLY_INSTALLED}" = "false" ]; then
  az config set core.allow_broker=true
  az account clear
  az login >> $log_filename
fi

#set azure subscription
az account set --subscription $AZURE_SUBSCRIPTION_NAME

is_valid_location

echo "Step 1/14 : Successfully logged into Azure"
echo "Step 1/14 : Successfully logged into Azure" >> $log_filename

#create if only if it does not exists
if az group show --name $RESOURCE_GROUP 2>&1 | grep -q "ResourceGroupNotFound"; then
  az group create --name $RESOURCE_GROUP --location $LOCATION >> $log_filename
  if [ $? -eq 0 ]; then
    echo "Step 2/14 : Successfully created resource group ${RESOURCE_GROUP}"
    echo "Step 2/14 : Successfully created resource group ${RESOURCE_GROUP}" >> $log_filename
  else
    echo "Step 2/14 : Failed to create resource group ${RESOURCE_GROUP}"
    echo "Step 2/14 : Failed to create resource group ${RESOURCE_GROUP}" >> $log_filename
    exit
  fi
else
  echo "Step 2/14 : Resource Group with name ${RESOURCE_GROUP} exists and skipping the creation of resource group";
  echo "Step 2/14 : Resource Group with name ${RESOURCE_GROUP} exists and skipping the creation of resource group" >> $log_filename
fi

if az storage account show --name $STORAGE_ACCOUNT --resource-group $RESOURCE_GROUP 2>&1 | grep -q "ResourceNotFound" ; then
  if az storage account show --name $STORAGE_ACCOUNT 2>&1 | grep -q "not found" ; then
    az storage account create --name ${STORAGE_ACCOUNT} --resource-group ${RESOURCE_GROUP} --location $LOCATION >> $log_filename
    if [ $? -eq 0 ]; then
      echo "Step 3/14 : Successfully created storage account ${STORAGE_ACCOUNT}"
      echo "Step 3/14 : Successfully created storage account ${STORAGE_ACCOUNT}" >> $log_filename
    else
      echo "Step 3/14 : Failed to create storage account ${STORAGE_ACCOUNT}"
      echo "Step 3/14 : Failed to create storage account ${STORAGE_ACCOUNT}" >> $log_filename
      exit
    fi
  else
      echo "Step 3/14 : Storage Account with name ${STORAGE_ACCOUNT} is already taken by other resource group, please use different storage account and try again"
      echo "Step 3/14 : Storage Account with name ${STORAGE_ACCOUNT} is already taken by other resource group, please use different storage account and try again" >> $log_filename
      exit
  fi
else
  echo "Step 3/14 : Storage Account with name ${STORAGE_ACCOUNT} exists and skipping the creation of storage account";
  echo "Step 3/14 : Storage Account with name ${STORAGE_ACCOUNT} exists and skipping the creation of storage account" >> $log_filename
fi

conn=$(az storage account show-connection-string --resource-group $RESOURCE_GROUP --name $STORAGE_ACCOUNT --query connectionString -o tsv)

if az storage container show --account-name $STORAGE_ACCOUNT --name $CONTAINER_NAME 2>&1 | grep -q "ContainerNotFound"; then
  az storage container create --name $CONTAINER_NAME --connection-string $conn >> $log_filename
  if [ $? -eq 0 ]; then
     echo "Step 4/14 : Successfully created container ${CONTAINER_NAME}"
     echo "Step 4/14 : Successfully created container ${CONTAINER_NAME}" >> $log_filename
  else
    echo "Step 4/14 : Failed to create container ${CONTAINER_NAME}"
    echo "Step 4/14 : Failed to create container ${CONTAINER_NAME}" >> $log_filename
    exit
  fi
else
  echo "Step 4/14 : Container with name ${CONTAINER_NAME} exists, skipping the creation of container";
  echo "Step 4/14 : Container with name ${CONTAINER_NAME} exists, skipping the creation of container" >> $log_filename
fi

az provider register --namespace Microsoft.EventGrid

echo "Step 5/14 : Successfully registered the namespace"
echo "Step 5/14 : Successfully registered the namespace" >> $log_filename

az provider show --namespace Microsoft.EventGrid --query "registrationState"

export subscriptionId="$(az account show --query id -o tsv)"

if az eventgrid system-topic list --resource-group $RESOURCE_GROUP 2>&1 | grep -q $TOPIC_NAME ; then
  echo "Step 6/14 : System topic with name ${TOPIC_NAME} already exists, skipping the creation of ${TOPIC_NAME} topic"
  echo "Step 6/14 : System topic with name ${TOPIC_NAME} already exists, skipping the creation of ${TOPIC_NAME} topic" >> $log_filename
else
  EXISTING_SYSTEM_TOPIC=$(az eventgrid system-topic list --subscription $subscriptionId --resource-group $RESOURCE_GROUP --query "[].source" --output json)
  if echo ${EXISTING_SYSTEM_TOPIC} | grep -q "/subscriptions/${subscriptionId}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Storage/storageAccounts/${STORAGE_ACCOUNT}" ; then
    echo "Step 6/14 : There already exists one system topic for the combination of resource group ${RESOURCE_GROUP} and storage account ${STORAGE_ACCOUNT}, Only one system topic is allowed per resource group and storage account combination, please choose different resource group or storage account"
    echo "Step 6/14 : There already exists one system topic for the combination of resource group ${RESOURCE_GROUP} and storage account ${STORAGE_ACCOUNT}, Only one system topic is allowed per resource group and storage account combination, please choose different resource group or storage account" >> $log_filename
    exit
  else
    az eventgrid system-topic create --name $TOPIC_NAME\
      --resource-group ${RESOURCE_GROUP} \
      --source /subscriptions/${subscriptionId}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Storage/storageAccounts/${STORAGE_ACCOUNT} \
      --topic-type microsoft.storage.storageaccounts \
      --location ${LOCATION} >> $log_filename
    if [ $? -eq 0 ]; then
      echo "Step 6/14 : Successfully created system-topic ${TOPIC_NAME}"
      echo "Step 6/14 : Successfully created system-topic ${TOPIC_NAME}" >> $log_filename
    else
      echo "Step 6/14 : Failed to create system-topic ${TOPIC_NAME}"
      echo "Step 6/14 : Failed to create system-topic ${TOPIC_NAME}" >> $log_filename
      exit
    fi

  fi

fi

if az functionapp show --name $APP_NAME --resource-group $RESOURCE_GROUP 2>&1 | grep -q "ResourceNotFound" ; then
  az functionapp create --resource-group ${RESOURCE_GROUP} \
    --consumption-plan-location ${LOCATION} \
    --runtime python \
    --runtime-version 3.9 \
    --functions-version 4 \
    --name ${APP_NAME} \
    --os-type linux \
    --assign-identity '[system]' \
    --storage-account ${STORAGE_ACCOUNT} >> $log_filename
    if [ $? -eq 0 ]; then
      echo "Step 7/14 : Successfully created function app ${APP_NAME}"
      echo "Step 7/14 : Successfully created function app ${APP_NAME}" >> $log_filename
    else
      echo "Step 7/14 : Failed create function app ${APP_NAME}"
      echo "Step 7/14 : Failed create function app ${APP_NAME}" >> $log_filename
      exit
    fi
else
    echo "Step 7/14 : App with name ${APP_NAME} exists and skipping the creation of ${APP_NAME} app";
    echo "Step 7/14 : App with name ${APP_NAME} exists and skipping the creation of ${APP_NAME} app" >> $log_filename
fi

if az keyvault show --name $KEY_VAULT_NAME --resource-group $RESOURCE_GROUP 2>&1 | grep -q "ResourceNotFound" ; then

  az keyvault create --name $KEY_VAULT_NAME --resource-group $RESOURCE_GROUP >> $log_filename
  if [ $? -eq 0 ]; then
    echo "Step 8/14 : Successfully created keyVault ${KEY_VAULT_NAME}"
    echo "Step 8/14 : Successfully created keyVault ${KEY_VAULT_NAME}" >> $log_filename
  else
    echo "Step 8/14 : Failed to create keyVault ${KEY_VAULT_NAME}"
    echo "Step 8/14 : Failed to create keyVault ${KEY_VAULT_NAME}" >> $log_filename
    exit
  fi

else
  echo "Step 8/14 : KeyVault with name ${KEY_VAULT_NAME} exists, skipping the creation of KeyVault";
  echo "Step 8/14 : KeyVault with name ${KEY_VAULT_NAME} exists, skipping the creation of KeyVault" >> $log_filename
fi

if az keyvault key show --vault-name $KEY_VAULT_NAME --name "RSA-PRIVATE-KEY" 2>&1 | grep -q "KeyNotFound"; then
  az keyvault key import --vault-name $KEY_VAULT_NAME --name "RSA-PRIVATE-KEY" --pem-file $PEM_FILE_PATH --protection software >> $log_filename
  if [ $? -eq 0 ]; then
    echo "Step 9/14 : Successfully created secret with name RSA-PRIVATE-KEY under KeyVault ${KEY_VAULT_NAME}"
    echo "Step 9/14 : Successfully created secret with name RSA-PRIVATE-KEY under KeyVault ${KEY_VAULT_NAME}" >> $log_filename
  else
    echo "Step 9/14 : Failed to create secret with name RSA-PRIVATE-KEY under KeyVault ${KEY_VAULT_NAME}"
    echo "Step 9/14 : Failed to create secret with name RSA-PRIVATE-KEY under KeyVault ${KEY_VAULT_NAME}" >> $log_filename
    exit
  fi
else
  echo "Step 9/14 : Key with name RSA-PRIVATE-KEY exists under KeyVault ${KEY_VAULT_NAME}, skipping the creation of RSA-PRIVATE-KEY";
  echo "Step 9/14 : Key with name RSA-PRIVATE-KEY exists under KeyVault ${KEY_VAULT_NAME}, skipping the creation of RSA-PRIVATE-KEY" >> $log_filename
fi

if az keyvault secret show --vault-name $KEY_VAULT_NAME --name "CONSUMER-KEY" 2>&1 | grep -q "SecretNotFound"; then
  az keyvault secret set --vault-name $KEY_VAULT_NAME --name "CONSUMER-KEY" --value $CONSUMER_KEY_VALUE >> $log_filename
  if [ $? -eq 0 ]; then
    echo "Step 10/14 : Successfully created key with name CONSUMER-KEY under ${KEY_VAULT_NAME}"
    echo "Step 10/14 : Successfully created key with name CONSUMER-KEY under ${KEY_VAULT_NAME}" >> $log_filename
  else
    echo "Step 10/14 : Failed to create key with name CONSUMER-KEY under ${KEY_VAULT_NAME}"
    echo "Step 10/14 : Failed to create key with name CONSUMER-KEY under ${KEY_VAULT_NAME}" >> $log_filename
    exit
  fi
else
  echo "Step 10/14 : Secret with name CONSUMER-KEY exists under KeyVault ${KEY_VAULT_NAME}, skipping the creation of CONSUMER-KEY";
  echo "Step 10/14 : Secret with name CONSUMER-KEY exists under KeyVault ${KEY_VAULT_NAME}, skipping the creation of CONSUMER-KEY" >> $log_filename
fi

az functionapp config appsettings set --name $APP_NAME \
  --resource-group ${RESOURCE_GROUP} \
  --settings SF_LOGIN_URL=$SF_LOGIN_URL \
  SF_AUDIENCE_URL=SF_AUDIENCE_URL \
  SF_USERNAME=$SF_USERNAME \
  KEY_VAULT_NAME=$KEY_VAULT_NAME >> $log_filename

echo "Step 11/14 : Successfully set config settings to function app with name ${APP_NAME}"
echo "Step 11/14 : Successfully set config settings to function app with name ${APP_NAME}" >> $log_filename

az functionapp deployment source config-zip --resource-group $RESOURCE_GROUP \
  --name $APP_NAME --src $SOURCE_CODE_LOCAL_PATH --build-remote true --verbose >> $log_filename

echo "Step 12/14 : Successfully deplopyed function app with name ${APP_NAME}"
echo "Step 12/14 : Successfully deplopyed function app with name ${APP_NAME}" >> $log_filename

appPrincipalIdentity="$(az functionapp show --name $APP_NAME --resource-group $RESOURCE_GROUP --query identity.principalId -o tsv)"

echo "Step 13/14 : appPrincipalIdentity is ${appPrincipalIdentity}"
echo "Step 13/14 : appPrincipalIdentity is ${appPrincipalIdentity}" >> $log_filename

az role assignment create --assignee-object-id ${appPrincipalIdentity} --role "Key Vault Crypto Officer" --scope /subscriptions/${subscriptionId}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.KeyVault/vaults/${KEY_VAULT_NAME}
az role assignment create --assignee-object-id ${appPrincipalIdentity} --role "Key Vault Secrets Officer" --scope /subscriptions/${subscriptionId}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.KeyVault/vaults/${KEY_VAULT_NAME}

echo "Step 13/14 : Successfully attached key vault Crypto and Secrets Officer role to key vault ${KEY_VAULT_NAME}"
echo "Step 13/14 : Successfully attached key vault Crypto and Secrets Officer role to key vault ${KEY_VAULT_NAME}" >> $log_filename

if az eventgrid system-topic event-subscription show --name $SUBSCRIPTION_NAME --resource-group $RESOURCE_GROUP --system-topic-name $TOPIC_NAME 2>&1 | grep -q "ResourceNotFound"; then
  az eventgrid system-topic event-subscription create --name ${SUBSCRIPTION_NAME} \
  --resource-group ${RESOURCE_GROUP} \
  --system-topic-name ${TOPIC_NAME} \
  --endpoint /subscriptions/${subscriptionId}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Web/sites/${APP_NAME}/functions/eventGridTrigger \
  --endpoint-type azurefunction \
  --event-delivery-schema eventgridschema \
  --included-event-types Microsoft.Storage.BlobCreated Microsoft.Storage.BlobDeleted >> $log_filename
  if [ $? -eq 0 ]; then
    echo "Step 14/14 : Successfully created subscription ${SUBSCRIPTION_NAME} to topic ${TOPIC_NAME}"
    echo "Step 14/14 : Successfully created subscription ${SUBSCRIPTION_NAME} to topic ${TOPIC_NAME}" >> $log_filename
  else
    echo "Step 14/14 : Faield to create subscription ${SUBSCRIPTION_NAME} to topic ${TOPIC_NAME}"
    echo "Step 14/14 : Faield to create subscription ${SUBSCRIPTION_NAME} to topic ${TOPIC_NAME}" >> $log_filename
    exit
  fi
else
  echo "Step 14/14 : subscriptions with name ${SUBSCRIPTION_NAME} to system-topic ${TOPIC_NAME} already exists, skipping the subscription of ${SUBSCRIPTION_NAME} to ${TOPIC_NAME} topic"
  echo "Step 14/14 : subscriptions with name ${SUBSCRIPTION_NAME} to system-topic ${TOPIC_NAME} already exists, skipping the subscription of ${SUBSCRIPTION_NAME} to ${TOPIC_NAME} topic" >> $log_filename
fi

echo "All the azure cloud function installer logs are logged to ${log_filename} file"

echo "AZURE EVENT NOTIFICATION SUCCESSFUL - Below is the summary of important resources"
echo "RESOURCE GROUP NAME: ${RESOURCE_GROUP}"
echo "STORAGE ACCOUNT NAME : ${STORAGE_ACCOUNT}"
echo "CONTAINER NAME : ${CONTAINER_NAME}"
echo "KEY VAULT NAME : ${KEY_VAULT_NAME}"
echo "FUNCTION APP NAME : ${APP_NAME}"
echo "SYSTEM TOPIC NAME : ${TOPIC_NAME}"
echo "SUBSCRIPTION_NAME : ${SUBSCRIPTION_NAME}"
echo "REGION / LOCATION : ${LOCATION}"
echo "As a next step, you can create the relevant parent and second level directories (if they don't exist) in the above ${CONTAINER_NAME} such that they align with the parent directory in Azure connector and the directory mentioned while UDLO creation"