#!/bin/bash

TARGET_USERS=20
SMALL_PAGE_SIZE=20
LARGE_PAGE_SIZE=100

DEPLOYMENTS=(
    "deploy_main"
    "deploy_branch_runtime"
    "deploy_branch_static"
)

deploy_main() {
    KIBANA_URL="" # Fill this in
    PASSWORD="" # Fill this in
    TYPE="main"
}

deploy_branch_runtime() {
    KIBANA_URL="" # Fill this in
    PASSWORD="" # Fill this in
    TYPE="branch"
}

deploy_branch_static() {
    KIBANA_URL="" # Fill this in
    PASSWORD="" # Fill this in
    TYPE="branch"
}

SESSION_NAME="k6-parallel"

# ==========================================
# Execution Logic
# ==========================================

mkdir -p results

# 1. Create a new detached session
tmux new-session -d -s $SESSION_NAME

# 2. Prepare the layout
# Calculate how many panes we need.
# The session starts with 1 window (pane 0). We need to split it N-1 times.
COUNT=${#DEPLOYMENTS[@]}

for (( i=1; i<$COUNT; i++ )); do
    tmux split-window -h
done

tmux select-layout even-horizontal

# 3. Run tests in each pane
for i in "${!DEPLOYMENTS[@]}"; do
    echo "Running test for ${DEPLOYMENTS[$i]} at $(date)"

    CONFIG_FUNC="${DEPLOYMENTS[$i]}"

    # Run the function to load variables for this deployment
    # We run it in a subshell or just evaluate it here to construct the command string
    # To keep it simple, we'll evaluate it in the current shell to get the values,
    # then pass them to the tmux command.

    (
        # Execute the config function to set vars
        $CONFIG_FUNC

        # Build the k6 command with all exported variables
        # We explicitly pass KIBANA_URL and PASSWORD.
        # If you add more vars, add them to the -e flags below.
        CMD="k6 run \\
            --out json=results/results.${DEPLOYMENTS[$i]}.json \\
            --address=localhost:656${i} \\
            -e KIBANA_URL='$KIBANA_URL' \\
            -e PASSWORD='$PASSWORD' \\
            -e TYPE='$TYPE' \\
            -e TARGET_USERS='$TARGET_USERS' \\
            -e SMALL_PAGE_SIZE='$SMALL_PAGE_SIZE' \\
            -e LARGE_PAGE_SIZE='$LARGE_PAGE_SIZE' \\
            k6-test.ts; \\
            node process-results.js results/results.${DEPLOYMENTS[$i]}.json | tee results/summary_${DEPLOYMENTS[$i]}.txt; \\
            echo 'Done. Press Enter to close'; \\
            read"

        # Send to tmux pane $i
        tmux send-keys -t $i "$CMD" C-m
    )
done

# 4. Attach to the session
tmux attach-session -t $SESSION_NAME
