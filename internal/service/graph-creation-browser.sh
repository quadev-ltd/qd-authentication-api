#!/bin/bash
set +x

MEMORY_TOOL_SRC_DIRECTORY=memory-tool-src
NOWTV_SRC_DIRECTORY=src
MEMORY_REPORT_DIRECTORY=memory-report-output-$INDEX
OUTPUT_FOLDER=memory-graph-output-$INDEX
INPUT_FOLDER=memory-report-output-$INDEX
INPUT_ARTIFACT_FOLDER=artifact-$INPUT_FOLDER
RESULT_ARTIFACT_FOLDER=artifact-$OUTPUT_FOLDER

function get_version() {
  if [ ! -d "$NOWTV_SRC_DIRECTORY" ]; then
    echo "$NOWTV_SRC_DIRECTORY folder does not exist."
    exit 1
  fi
  if [ -d "$NOWTV_SRC_DIRECTORY/.git/resource" ]; then
    VERSION="$(cut -c1-7 < $NOWTV_SRC_DIRECTORY/.git/resource/head_sha)"
  else
    VERSION="$(cut -c1-7 < $NOWTV_SRC_DIRECTORY/.git/HEAD)"
  fi
}

function set_up_memory_tool() {
  if [ -d "$MEMORY_TOOL_SRC_DIRECTORY" ]; then
    cd "$MEMORY_TOOL_SRC_DIRECTORY"
    yarn install
    yarn start:graph-image > app.log 2>&1 &
    cd -
  else
    echo "$MEMORY_TOOL_SRC_DIRECTORY memory tool folder does not exist."
    exit 1
  fi
}

function wait_for_server() {
  local port=3001
  local timeout=30
  local wait_interval=1
  local counter=0

  echo "Waiting for server to start on port $port..."
  while ! nc -z localhost "$port"; do
    sleep $wait_interval
    counter=$((counter + wait_interval))

    if [ $counter -ge $timeout ]; then
      echo "Server did not start within $timeout seconds."
      exit 1
    fi
  done
  echo "Server is now running on port $port."
}

function main() {
  get_version
  set_up_memory_tool
  wait_for_server
  #  check that $MEMORY_REPORT_DIRECTORY folder exists and it contains .json files
  if [ ! -d "$MEMORY_REPORT_DIRECTORY" ]; then
    echo "$MEMORY_REPORT_DIRECTORY folder does not exist or it does not contain artifact files."
    exit 1
  fi

  mkdir $OUTPUT_FOLDER/$RESULT_ARTIFACT_FOLDER
  echo "INPUT_ARTIFACT_FOLDER: $INPUT_ARTIFACT_FOLDER"
  JSON_FILES=$(find $INPUT_FOLDER/$INPUT_ARTIFACT_FOLDER -name "memory-usage-report*.json" -type f)
  for JSON_FILE in $JSON_FILES; do
    JSON_CONTENT=$(cat "$JSON_FILE")
    FILE_NAME=$(basename "$JSON_FILE" .json)

    # Send the JSON content in a POST request with curl
    curl -X POST -H "Content-Type: application/json" -d "$JSON_CONTENT" http://localhost:3001/graph -o "$OUTPUT_FOLDER/$RESULT_ARTIFACT_FOLDER/$FILE_NAME-graph.png"
  done
}

main
