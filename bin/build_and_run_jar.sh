#!/bin/sh

# DEPRECATED. Interactive script to build a new jar.
# TODO: Remove this file once index.html copying logic is moved into
# distributions/demo-google-deployment/api/build.gradle.
#
# Usage: ./config/gcp/build_jar.sh <binary> <env> <cloud> <distribution>
# - binary is required and specifies which server to build.
#     This should be one of: worker, gateway
#     ex: gateway will build a distribution of the portability-gateway binary
# - env is the environment you would like to build in. This should correspond to an environment dir
#     in config/environments. Settings for this environment are copied into the binary.
# - cloud is required and specifies which cloud environment to use
#     This should be one of the supported cloud extensions
#     ex: 'google' or 'microsoft'
# - distribution
#     this is optional and specifies which distribution to build. If not specified, will use the default build
#     ex: binary=gateway and distribution=prod, will build the jar under distributions/gateway-prod
#         binary=gateway and distribution=default, will build the jar under distributions/gateway-default
# Must be run from the root source directory data-portability/

if [[ $(pwd) != */data-transfer-project ]]; then
  echo "Please run out of /data-transfer-project directory. Aborting."
  exit 1
fi

if [ -z $1 ]; then
  echo "ERROR: Must provide a binary: 'api', 'gateway', or 'worker'"
  exit 1
fi

if [ -z $2 ]; then
  echo "ERROR: Must provide an environment, e.g. 'local', 'test', 'qa', or 'prod'"
  exit 1
fi

# TODO: this should be pulled in from the environment configuration scrips.
if [ -z $3 ]; then
  echo "ERROR: Must provide a cloud type, e.g. 'local', 'google', or 'microsoft'"
  exit 1
fi

DISTRO=$4
if [ -z $4]; then
  DISTRO="default"
fi

BINARY=$1
ENV=$2
CLOUD=$3
SRC_DIR="distributions/$BINARY-$DISTRO"
DEBUG_PORT=5005
if [[ $BINARY == "worker" ]]; then
  DEBUG_PORT=5006
fi

gradle=$(which gradle)|| { echo "Gradle (gradle) not found. Please install it and try again." >&2; exit 1; }

# Copy settings yaml files from ENV/settings/ into $SRC_DIR/src/main/resources/
# TODO: this script should take cloud extension name as a param, in addition to ENV.
# It should copy common and api/worker settings from extension-cloud-dir/config/ into config/, and
# similarly, env-specific settings from extension-cloud-dir/config/environments/$ENV/settings.yaml
# into config/env/.
DEST_RESOURCES_PATH="$SRC_DIR/src/main/resources"
DEST_SETTINGS_PATH="$DEST_RESOURCES_PATH/settings/"
if [[ -e ${DEST_SETTINGS_PATH} ]]; then
  echo -e "\nRemoving old settings folder"
  rm -rf ${DEST_SETTINGS_PATH}
  if [[ -e ${DEST_SETTINGS_PATH} ]]; then
    echo "Problem removing old settings.yaml. Aborting."
    exit 1
  fi
fi
mkdir $DEST_SETTINGS_PATH
SRC_RESOURCES_PATH="config/environments/$ENV"
SRC_SETTINGS_PATH="$SRC_RESOURCES_PATH/settings/"
echo -e "Copying common.yaml from $SRC_SETTINGS_PATH to $DEST_SETTINGS_PATH"
cp "${SRC_SETTINGS_PATH}common.yaml" "${DEST_SETTINGS_PATH}common.yaml"
if [[ ! -e "${DEST_SETTINGS_PATH}common.yaml" ]]; then
  echo "Problem copying settings/common.yaml. Aborting."
  exit 1
fi

if [[ -e "${SRC_RESOURCES_PATH}/log4j.properties" ]]; then
  echo "copying log4j.properties to ${DEST_RESOURCES_PATH}."
  cp "${SRC_RESOURCES_PATH}/log4j.properties" "${DEST_RESOURCES_PATH}/log4j.properties"
  if [[ ! -e "${DEST_RESOURCES_PATH}/log4j.properties" ]]; then
    echo "Problem copying log4j.properties. Aborting."
    exit 1
  fi
fi

if [[ $BINARY == "api" || $BINARY == "gateway" ]]; then
  echo -e "Copying api.yaml from $SRC_SETTINGS_PATH to $DEST_SETTINGS_PATH"
  cp "${SRC_SETTINGS_PATH}api.yaml" "${DEST_SETTINGS_PATH}api.yaml"
  if [[ ! -e "${SRC_SETTINGS_PATH}api.yaml" ]]; then
    echo "Problem copying settings/api.yaml. Aborting."
    exit 1
  fi
fi
echo -e "Copied settings/"

# secrets.csv is deprecated except for local development. Delete any old versions of this file
# so it doesn't make its way into our jar, even though our binary is configured to ignore it
# for non-local environments.
SECRETS_CSV_DEST_PATH="$SRC_DIR/src/main/resources/secrets.csv"
if [[ -e ${SECRETS_CSV_DEST_PATH} ]]; then
  echo -e "\nRemoving old secrets.csv"
  rm ${SECRETS_CSV_DEST_PATH}
  if [[ -e ${SECRETS_CSV_DEST_PATH} ]]; then
    echo "Problem removing old secrets.csv. Aborting."
    exit 1
  fi
fi

# Local uses index from ng serve, everything else uses index built from
# build_and_deploy_static_content.sh
if [[ ${ENV} != "local" ]]; then
  # Copy index.html from local/ or test/ into $SRC_DIR/src/main/resources/static/index.html
  INDEX_HTML_DEST_PATH_DIR="$SRC_DIR/src/main/resources/static/"
  INDEX_HTML_DEST_PATH="$INDEX_HTML_DEST_PATH_DIR/index.html"
  if [[ ! -e $INDEX_HTML_DEST_PATH_DIR ]]; then
    mkdir $INDEX_HTML_DEST_PATH_DIR
  fi
  if [[ -e ${INDEX_HTML_DEST_PATH} ]]; then
    echo -e "\nRemoving old index.html"
    rm ${INDEX_HTML_DEST_PATH}
    if [[ -e ${INDEX_HTML_DEST_PATH} ]]; then
      echo "Problem removing old index.html. Aborting."
      exit 1
    fi
  fi
  INDEX_HTML_SRC_PATH="config/environments/$ENV/index.html"
  echo -e "Copying index.html from $INDEX_HTML_SRC_PATH to $INDEX_HTML_DEST_PATH"
  cp $INDEX_HTML_SRC_PATH $INDEX_HTML_DEST_PATH
  if [[ ! -e ${INDEX_HTML_DEST_PATH} ]]; then
    echo "Problem copying index.html. Aborting."
    exit 1
  fi
  echo -e "Copied index.html"
else
  # secrets.csv in our binary is only used for local development. For prod, app keys & secrets
  # are stored in GCS and secrets are encrypted with KMS.
  SECRETS_CSV_SRC_PATH="config/environments/$ENV/secrets.csv"
  echo -e "Copying secrets.csv from $SECRETS_CSV_SRC_PATH to $SECRETS_CSV_DEST_PATH"
  cp $SECRETS_CSV_SRC_PATH $SECRETS_CSV_DEST_PATH
  if [[ ! -e ${SECRETS_CSV_DEST_PATH} ]]; then
    echo "Problem copying secrets.csv. Aborting."
    exit 1
  fi
  echo -e "Copied secrets\n"
fi

# Compile jar with gradle.
echo -e "\nCompiling and packaging...\n"

gradle wrapper
./gradlew -PcloudType=$CLOUD clean build shadowJar

# TODO: Exit in case of error compiling

read -p "Would you like to run the app jar at this time? (Y/n): " response
if [[ ! ${response} =~ ^(no|n| ) ]]; then
  COMMAND="java -jar -Xdebug -Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=$DEBUG_PORT $SRC_DIR/build/libs/$BINARY-$DISTRO-all.jar"
  echo -e "running $COMMAND"
  $COMMAND
fi
