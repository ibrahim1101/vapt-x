#====================================================================================================
# START - Testing Protocol - DO NOT EDIT OR REMOVE THIS SECTION
#====================================================================================================

# THIS SECTION CONTAINS CRITICAL TESTING INSTRUCTIONS FOR BOTH AGENTS
# BOTH MAIN_AGENT AND TESTING_AGENT MUST PRESERVE THIS ENTIRE BLOCK

# Communication Protocol:
# If the `testing_agent` is available, main agent should delegate all testing tasks to it.
#
# You have access to a file called `test_result.md`. This file contains the complete testing state
# and history, and is the primary means of communication between main and the testing agent.
#
# Main and testing agents must follow this exact format to maintain testing data. 
# The testing data must be entered in yaml format Below is the data structure:
# 
## user_problem_statement: {problem_statement}
## backend:
##   - task: "Task name"
##     implemented: true
##     working: true  # or false or "NA"
##     file: "file_path.py"
##     stuck_count: 0
##     priority: "high"  # or "medium" or "low"
##     needs_retesting: false
##     status_history:
##         -working: true  # or false or "NA"
##         -agent: "main"  # or "testing" or "user"
##         -comment: "Detailed comment about status"
##
## frontend:
##   - task: "Task name"
##     implemented: true
##     working: true  # or false or "NA"
##     file: "file_path.js"
##     stuck_count: 0
##     priority: "high"  # or "medium" or "low"
##     needs_retesting: false
##     status_history:
##         -working: true  # or false or "NA"
##         -agent: "main"  # or "testing" or "user"
##         -comment: "Detailed comment about status"
##
## metadata:
##   created_by: "main_agent"
##   version: "1.0"
##   test_sequence: 0
##   run_ui: false
##
## test_plan:
##   current_focus:
##     - "Task name 1"
##     - "Task name 2"
##   stuck_tasks:
##     - "Task name with persistent issues"
##   test_all: false
##   test_priority: "high_first"  # or "sequential" or "stuck_first"
##
## agent_communication:
##     -agent: "main"  # or "testing" or "user"
##     -message: "Communication message between agents"

# Protocol Guidelines for Main agent
#
# 1. Update Test Result File Before Testing:
#    - Main agent must always update the `test_result.md` file before calling the testing agent
#    - Add implementation details to the status_history
#    - Set `needs_retesting` to true for tasks that need testing
#    - Update the `test_plan` section to guide testing priorities
#    - Add a message to `agent_communication` explaining what you've done
#
# 2. Incorporate User Feedback:
#    - When a user provides feedback that something is or isn't working, add this information to the relevant task's status_history
#    - Update the working status based on user feedback
#    - If a user reports an issue with a task that was marked as working, increment the stuck_count
#    - Whenever user reports issue in the app, if we have testing agent and task_result.md file so find the appropriate task for that and append in status_history of that task to contain the user concern and problem as well 
#
# 3. Track Stuck Tasks:
#    - Monitor which tasks have high stuck_count values or where you are fixing same issue again and again, analyze that when you read task_result.md
#    - For persistent issues, use websearch tool to find solutions
#    - Pay special attention to tasks in the stuck_tasks list
#    - When you fix an issue with a stuck task, don't reset the stuck_count until the testing agent confirms it's working
#
# 4. Provide Context to Testing Agent:
#    - When calling the testing agent, provide clear instructions about:
#      - Which tasks need testing (reference the test_plan)
#      - Any authentication details or configuration needed
#      - Specific test scenarios to focus on
#      - Any known issues or edge cases to verify
#
# 5. Call the testing agent with specific instructions referring to test_result.md
#
# IMPORTANT: Main agent must ALWAYS update test_result.md BEFORE calling the testing agent, as it relies on this file to understand what to test next.

#====================================================================================================
# END - Testing Protocol - DO NOT EDIT OR REMOVE THIS SECTION
#====================================================================================================



#====================================================================================================
# Testing Data - Main Agent and testing sub agent both should log testing data below this section
#====================================================================================================

user_problem_statement: "VAPT-X full core authorized assessment lifecycle, real safe/Nmap scans and five report parsers; no fake findings; organization RBAC; evidence, PDF, remediation, retest, Claude."
backend:
  - task: "Complete authenticated core workflow and tenant isolation"
    implemented: true
    working: NA
    file: "backend/auth.py, repository.py, workflow.py, scanners.py, importers.py, evidence.py, reporting.py, analyst.py"
    stuck_count: 0
    priority: high
    needs_retesting: true
    status_history:
      - working: NA
        agent: main
        comment: "All core routes implemented. Actual owner training safe scan completed with five genuine observations, PDF generated via authenticated API. Full functional and denial matrix not yet tested."
frontend:
  - task: "Connected desktop and mobile workspace lifecycle"
    implemented: true
    working: NA
    file: "frontend/src/App.js and components/workspace-*.jsx, dashboard.jsx, access.jsx"
    stuck_count: 0
    priority: high
    needs_retesting: true
    status_history:
      - working: NA
        agent: main
        comment: "Production build passes. Desktop/mobile login smoke screenshots show no overflow. Need full authenticated browser flows and all pages at 390px."
metadata:
  created_by: main
  version: '1.0'
  test_sequence: 0
  run_ui: true
test_plan:
  current_focus:
    - "Full lifecycle and denial matrix"
    - "Real Nmap and five import formats"
    - "Evidence PDF retest comparison Claude multi-turn and persistence"
    - "Authenticated desktop/mobile UI"
  stuck_tasks: []
  test_all: true
  test_priority: high_first
agent_communication:
  - agent: main
    message: "Use actual owner credentials from memory/test_credentials.md and current preview URL from frontend/.env. Origin + X-CSRF-Token + session cookies required for mutations; X-Org-Id for tenant. Never scan unrelated third parties. Use training://local managed target. Owner workspace contains one real training assessment. Please create durable pytest regressions under backend/tests."
