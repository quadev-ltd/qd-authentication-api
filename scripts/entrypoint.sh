#!/bin/sh

# Ensure APP_ENV is set
if [ -z "$APP_ENV" ]; then
  APP_ENV=dev
fi

# Construct the variable name dynamically
ENV_PREFIX=$(echo "$APP_ENV" | tr '[:lower:]' '[:upper:]')
FIREBASE_CONFIG_VAR="${ENV_PREFIX}_ENV_FIREBASE_CONFIG_PATH"

# Get the value of the dynamically constructed variable name
FIREBASE_CONFIG_PATH=$(eval echo \$$FIREBASE_CONFIG_VAR)

# Check if the constructed environment variable is set
if [ -z "$FIREBASE_CONFIG_PATH" ]; then
  echo "Error: ${FIREBASE_CONFIG_VAR} is not set."
  exit 1
fi

# Decode the base64 encoded service account and write to the file
echo $FIREBASE_SERVICE_ACCOUNT_BASE64 | base64 -d > "$FIREBASE_CONFIG_PATH"

# Proceed with the rest of the entrypoint script or the application start
exec "$@"