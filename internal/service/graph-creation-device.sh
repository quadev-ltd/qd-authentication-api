#!/bin/bash
set +x

MEMORY_TOOL_SRC_DIRECTORY=memory-tool-src
NOWTV_SRC_DIRECTORY=src
MEMORY_REPORT_DIRECTORY=artifacts-memory-report-json

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
  if [ ! -d "$MEMORY_REPORT_DIRECTORY" ] || [ -z "$(find $MEMORY_REPORT_DIRECTORY -name "*.tar.gz" -type f)" ]; then
    echo "$MEMORY_REPORT_DIRECTORY folder does not exist or it does not contain artifact files."
    exit 1
  fi

  COMPRESSED_ARTIFACT=$(find $MEMORY_REPORT_DIRECTORY -name "*.tar.gz" -type f)
  OUTPUT_ARTIFACT_FOLDER="artifacts-output"

  tar -xzf $COMPRESSED_ARTIFACT -C $MEMORY_REPORT_DIRECTORY

  GRAPHS_FOLDER="graphs"
  mkdir $OUTPUT_ARTIFACT_FOLDER/$GRAPHS_FOLDER

  EXTRACTED_ARTIFACT_FOLDER="${COMPRESSED_ARTIFACT%.tar.gz}"
  JSON_FILES=$(find $EXTRACTED_ARTIFACT_FOLDER -name "memory-usage-report*.json" -type f)
  for JSON_FILE in $JSON_FILES; do
    JSON_CONTENT=$(cat "$JSON_FILE")
    FILE_NAME=$(basename "$JSON_FILE" .json)

    # Send the JSON content in a POST request with curl
    curl -X POST -H "Content-Type: application/json" -d "$JSON_CONTENT" http://localhost:3001/graph -o "$OUTPUT_ARTIFACT_FOLDER/$GRAPHS_FOLDER/artifact-$FILE_NAME-graph.png"
  done

  tar -czf "$OUTPUT_ARTIFACT_FOLDER/artifact-graphs.tar.gz" -C $OUTPUT_ARTIFACT_FOLDER $GRAPHS_FOLDER
}

main
