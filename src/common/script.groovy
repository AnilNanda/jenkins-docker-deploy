import net.sf.json.JSONObject
import net.sf.json.JSONArray

def random

NOTIFICATION_USER = "Jenkins"
HIPCHAT_SERVER = "sme-apps.slack.com"
APPLICATION_JSON="APPLICATION_JSON"
JENKINS_SLACK_CREDENTIALS = "slack-jenkins"
SMART_CHECK_HOST_URL = "https://smart-check.smeperforce.com"

FAIL_ON_VULNERABILITIES_LIST = ["defcon1", "critical", "high"]
random = null
smartCheckToken = null
smartCheckSessionId = null
smartCheckLocalSession = [:]
SMART_CHECK_SCAN_WAIT_STATES = ["pending", "in-progress"]

//
CHATOPS_STATUS_COLOR_MAP = ["STARTED":"#36A64F", "UNSTABLE":"#f4ef02", "FAILURE":"#f40202", "SUCCESS":"#36A64F", "ABORTED":"#706f63"]

def getRandom(){
if (random){
	return random
} else{
	random= new Random()
	return random
}
}

def createDir(dirName){
	sh "mkdir -p ${dirName}"
}


def setAWSRegion(region) {

sh "aws configure set region ${region}"
}

def cleanWs(){
	echo "Clean workspace at ${pwd()}"
	sh "rm -rf ${pwd()}/*"
}

def getgitkey() {
  echo "Fetching pvt rsa key from secretsmanager to access gitlab"
  sh "mkdir -p /home/jenkins/.ssh && touch /home/jenkins/.ssh/known_hosts && ssh-keyscan git.smeperforce.com >> /home/jenkins/.ssh/known_hosts"
  sh "aws configure set default.region us-east-1"
  sh "aws secretsmanager get-secret-value --secret-id jenkins-slave-key | jq --raw-output '.SecretString' >> /home/jenkins/.ssh/id_rsa"
  sh "chmod 400 /home/jenkins/.ssh/id_rsa"
}

def artifactsToS3(c1,c2) {
  sh "mkdir -p /home/jenkins/.aws && touch /home/jenkins/.aws/credentials1 && touch /home/jenkins/.aws/credentials2"
  sh "aws configure set default.region us-east-1"
  sh "aws secretsmanager get-secret-value --secret-id promo-dev-jenkins | jq --raw-output '.SecretString' |jq -r .API_KEY  >> /home/jenkins/.aws/credentials1"
  sh "aws secretsmanager get-secret-value --secret-id promo-dev-jenkins | jq --raw-output '.SecretString' |jq -r .SECRET_KEY  >> /home/jenkins/.aws/credentials2"
  env.FILENAME = readFile '/home/jenkins/.aws/credentials1'
  c1 = "${env.FILENAME}"
  sh "aws configure set aws_access_key_id ${c1}"
  env.FILENAME1 = readFile '/home/jenkins/.aws/credentials2'
  c2 = "${env.FILENAME1}"
  sh "aws configure set aws_secret_access_key ${c2}"
}



def cleanUpDockerImages() {
	echo "Clean un-used docker images"
	sh "docker system prune -af"
}

def checkoutGitFromScm(scm){
	checkout changelog: true, poll: true,
	scm: [
		$class: 'GitSCM',
		branches: scm.branches,            
		doGenerateSubmoduleConfigurations: scm.doGenerateSubmoduleConfigurations,            
		extensions: scm.extensions,
            userRemoteConfigs: scm.userRemoteConfigs
        ]
}

def checkoutGitToDir(repository, branch, directory, poll) {
    checkout changelog: false, poll: poll,
        scm: [
            $class: 'GitSCM',
            branches: [[name: branch]],
            userRemoteConfigs: [[
            name: 'origin',
            url: repository
            ]],
            extensions: [[$class: 'RelativeTargetDirectory', relativeTargetDir: directory]]
        ]
}


def notifyBuild(status) {
    def statusStr = status.toString()
    def color = CHATOPS_STATUS_COLOR_MAP.containsKey(statusStr) ? CHATOPS_STATUS_COLOR_MAP.get(statusStr) : "PURPLE"
//    def color = "#36A64F" 
    if(!params.containsKey("MUTE_HIPCHAT") || !params["MUTE_HIPCHAT"]) {
        if(!params.containsKey("SLACK_CHANNEL") || !params["SLACK_CHANNEL"]) {
            logStep "SLACK_CHANNEL parameter is not defined or empty. Please pass a parameter as SLACK_CHANNEL with appropriate channel value to the build job."
        } else {
            slackSend (
            color: "${color}", notify: true, credentialId: JENKINS_SLACK_CREDENTIALS,
            message: "${statusStr}: Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]'", 
            channel: params.SLACK_CHANNEL,
//            sendAs: NOTIFICATION_USER, server: SLACK_SERVER, textFormat: true, v2enabled: true
            )
        }
    }
}


// this is a simply way of reading maven properties without any plugins
// if you need additional properties, we suggest to make use of the 
// Pipeline Utilities Plugin (see readMavenPom)
// https://jenkins.io/doc/pipeline/steps/pipeline-utility-steps/
def getMavenArtifactId() {
    def matcher = readFile('pom.xml') =~ '<artifactId>(.+?)</artifactId>'
    matcher ? matcher[0][1] : null
}
def getMavenArtifactVersion() {
    def matcher = readFile('pom.xml') =~ '<version>(.+?)</version>'
    matcher ? matcher[0][1] : null
}

// starts a container with some random settings to avoid conflcits with others
def startContainer(image, namePrefix, containerPort) {
    echo "starting..."
    def randomName = "${namePrefix} ${UUID.randomUUID().toString()}"
    def randomPort = 9000 + getRandom().nextInt(40000)

    echo "Starting ${randomName} at ${randomPort}:${containerPort} with image ${image}"
    sh "sudo docker run -d -p ${randomPort}:${containerPort} --name=${randomName} ${image}"
    sh "sudo docker ps --filter \"name=${randomName}\""

    return [randomName, randomPort]
}

// tries to stop and then remove the container
def removeContainerFromNode(String containerName) {
    try {
      sh "sudo docker kill ${containerName}"
    }
    catch (e) {
      echo "error killing the container : ${e.message}"
    }
    try {
      sh "sudo docker rm ${containerName}"
    }
    catch (e) {
      echo "error killing the container : ${e.message}"
    }
}

// Instead of prefixing and exposing the AWS credentials, we use `withCredentials` here.
def runAWSCmd(credentials, returnStdout, returnStatus, shCommand) {
    def localResultHolder
    withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', credentialsId: credentials, variable: 'AWS_ACCESS_KEY_ID']]) {
        sh "export AWS_ACCESS_KEY_ID=${env.AWS_ACCESS_KEY_ID}"
        sh "export AWS_SECRET_ACCESS_KEY=${env.AWS_SECRET_ACCESS_KEY}"
        localResultHolder = sh(returnStdout: returnStdout, returnStatus: returnStatus, script: shCommand)
    }

  return localResultHolder;
}

def logStep(String message) {
    echo "[currentBuild.result]: ${currentBuild.result}"
    def separator = "*".multiply(90)
    log = "\n\n${separator}\n****    ${message}\n${separator}"
    echo log
}

def convertPortMappingToJSONArrayString(String portMappingsList) {
	if (portMappingsList?.trim()) {
	    def portMapList = portMappingsList.split(',')
	    portMappingJsonArray = new JSONArray() 
	    for (int i = 0; i < portMapList.size(); i++) {
	        portMap = portMapList[i].split(':')
	        portMappingJsonObject = new JSONObject()
	        portMappingJsonObject.element("hostPort", portMap[0].toInteger())
	        portMappingJsonObject.element("containerPort", portMap[1].toInteger())
	        portMappingJsonArray.element(portMappingJsonObject)
	    }
	    return portMappingJsonArray.toString()
    } 
    return ""
}

//Mount Points
def convertMountPointToJSONArrayString(String mountPointList) {
	def mountPoints = mountPointList.split(',')
    mountPointJsonArray = new JSONArray() 
    for (int i = 0; i < mountPoints.size(); i++) {
        mountMap = mountPoints[i].split(':')
        mountPointJsonObject = new JSONObject()
        mountPointJsonObject.element("containerPath", mountMap[0])
        mountPointJsonObject.element("sourceVolume", mountMap[1])
        mountPointJsonArray.element(mountPointJsonObject)
    }
    return mountPointJsonArray.toString()
}

//Volumes
def convertVolumesToJSONArrayString(String volumeList) {
	def volumes = volumeList.split(',')
    volumeJsonArray = new JSONArray() 
    for (int i = 0; i < volumes.size(); i++) {
        volMap = volumes[i].split(':')
        //volumeJsonObject = new JSONObject()
        //volumeJsonObject.element("name", volMap[0])
        //volumeJsonObject.element("sourcePath", volMap[1])
        //volumeJsonArray.element(volumeJsonObject)
        volumeJsonObject = new JSONObject()
        volumeJsonObject.element("name", volMap[0])
         
        hostJsonObject = new JSONObject()
        hostJsonObject.element("sourcePath", volMap[1])
        volumeJsonObject.element("host", hostJsonObject)
            
        volumeJsonArray.element(volumeJsonObject)
        //volumeJsonArray.element(hostJsonObject)
    }
    return volumeJsonArray.toString()
}

//Convert environment variables into json string array. Example input "port:8080,env:stage" 
def convertEnvironmentVariableToJSONArrayString(String envList) {
    def envs = envList.split(',')
    envJsonArray = new JSONArray() 
    for (int i = 0; i < envs.size(); i++) {
        envMap = envs[i].split(':')
        envJsonObject = new JSONObject()
        envJsonObject.element("name", envMap[0])
        envJsonObject.element("value", envMap[1])
        envJsonArray.element(envJsonObject)
    }
    return envJsonArray.toString()
}

def getCurrentTaskArn(credentials, clusterName, serviceName) {
    createDir("tmp")
    runAWSCmd(credentials, false, false, """aws ecs describe-services \
        --services ${serviceName} \
        --cluster ${clusterName} \
        --query services[0].taskDefinition \
        --output text \
        > tmp/describe-services""")
    String currentTaskArn = readFile("tmp/describe-services").trim()
    echo "Currently ${currentTaskArn} is deployed for ${serviceName}"
    return currentTaskArn
}

def registerTaskDefinition(credentials, filePath) {
    createDir("tmp")
    logStep "Registering task definition for service ${SERVICE_NAME}"

    // Register task def.
    runAWSCmd(credentials, false, false, """aws ecs register-task-definition \
        --query taskDefinition.taskDefinitionArn \
        --output text \
        --cli-input-json ${filePath} \
        > tmp/task-definition-arn""")
    String taskDefinitionArn = readFile("tmp/task-definition-arn").trim()

    echo "Updated taskDefinitionArn: ${taskDefinitionArn}"
    return taskDefinitionArn
}



def waitForEcsDeployment(credentials, services, clusterName) {
    createDir("tmp")
    /*
        Wait until JMESPath query length(services[?!(length(deployments) == 1 &&runningCount == desiredCount)]) == 0 returns True when polling with describe-services.
        It will poll every 15 seconds until a successful state has been reached.
        This will exit with a return code of 255 after 40 failed checks
    */
    def status = runAWSCmd(credentials, false, true, """aws ecs wait services-stable \
            --services ${services} \
            --cluster ${clusterName} \
            2> tmp/service-stable""")
    if (status != 0) {
        def output = readFile("tmp/service-stable").trim()
        logStep("Services: ${services} is unstable. \nReason: ${output}")
        return false;
    }

    logStep("Deployment was successful.")
    return true;
}

/*
    This method was intended to be used in conjunction with waitForDeployment.
    waitForDeployment is deprecated, instead use waitForEcsDeployment.
*/
def getDeploymentID(credentials, serviceName, clusterName) {
    createDir("tmp")
    runAWSCmd(credentials, false, false, """aws ecs describe-services \
        --services ${serviceName} \
        --cluster ${clusterName} \
        --query 'services[0].deployments[?status==`PRIMARY`].id' \
        --output text \
        > tmp/deployment-id""")
    String deploymentID = readFile("tmp/deployment-id").trim()
    echo "Primary deploymentID: ${deploymentID} for service: ${serviceName}"
    return deploymentID
}

/*
    Deprecated
    Dont use the method below.
    Instead use waitForEcsDeployment
*/
def waitForDeployment(credentials, serviceName, clusterName, taskDefinition, deploymentID, maxDeployWaitMins, afterDeployWaitMins) {
    createDir("tmp")
    counter = maxDeployWaitMins * 2;
    while (counter > 0) {
        //determine tasks for service
        runAWSCmd(credentials, false, false, """aws ecs list-tasks \
            --service-name ${serviceName} \
            --cluster ${clusterName} \
            --query taskArns[*] \
            --output json \
            > tmp/taskArns""")
        
        taskArnsList = readFile("tmp/taskArns").trim()
        echo "${taskArnsList}"
        taskArns = parseJSON(taskArnsList)

        logStep("checking status... counter: ${counter}")
        success = checkTasksStatus(credentials, taskArns, clusterName, taskDefinition, deploymentID)

        if (success) {
            echo "Success! Waiting for after deployment... (2 Minutes) Time: ${new Date()} "
            sleep time: afterDeployWaitMins, unit: 'MINUTES'
            return true;
        } else {
            counter = counter - 1
        }
    }

    // Check for deployments failed, max attempts reached.
    return false;
}

/*
    This method was intended to be used in conjunction with waitForDeployment.
    waitForDeployment is deprecated, instead use waitForEcsDeployment.
*/
def checkTasksStatus(credentials, taskArns, clusterName, taskDefinition, deploymentID) {
    createDir("tmp")
    if(taskArns.size() == 0) {
        logStep("TaskArns list is empty. \nWaiting for updates... (30 Seconds) Time: ${new Date()} ")
        sleep time: 30, unit: 'SECONDS'
        return false
    }

    taskList = taskArns.join(" ")

    runAWSCmd(credentials, false, false, """aws ecs describe-tasks \
        --tasks ${taskList} \
        --cluster ${clusterName} \
        --output json \
        --query "tasks[*].{lastStatus:lastStatus,taskDefinition:taskDefinitionArn,startedBy:startedBy}" \
        > tmp/taskStatus """)

    result = readFile("tmp/taskStatus").trim()
    taskStatus = parseJSON(result)

    String statusText = ''
    for (int i = 0; i < taskStatus.size(); i++) {
        task = taskStatus[i]
        lastStatus = task.get("lastStatus")
        currentTaskDefinition = task.get("taskDefinition")
        startedBy = task.get("startedBy")
        statusText = statusText + "#### taskDefinition: ${currentTaskDefinition}, lastStatus: ${lastStatus}, deploymentID: ${startedBy}\n"
    }
    echo "#### Looking for taskDefinition: ${taskDefinition}, lastStatus: RUNNING, deploymentID: ${deploymentID}\n#### Currently Running Tasks: \n"+statusText

    for (int i = 0; i < taskStatus.size(); i++) {
        task = taskStatus[i]
        lastStatus = task.get("lastStatus")
        currentTaskDefinition = task.get("taskDefinition")
        startedBy = task.get("startedBy")

        if (lastStatus != "RUNNING" || !currentTaskDefinition.endsWith(taskDefinition) || !startedBy.endsWith(deploymentID)) {
            echo "Waiting for updates... (30 Seconds) Time: ${new Date()} "
            sleep time: 30, unit: 'SECONDS'
            return false
        }
    }
    return true
}

def scanContainerImage(smartCheckRegistryName, repositoryName, imageTag, maxTimeInMins) {
    def scanId = startImageScanFromRegistry(smartCheckRegistryName, repositoryName, imageTag).get("id")
    return waitForImageScanCompletion(scanId, maxTimeInMins)
}

def getSmartCheckToken() {
    if (!smartCheckLocalSession.get("id") || smartCheckLocalSession.expiry <= new Date()) {
        createNewLocalSession()
    }
    return smartCheckLocalSession.get("token")
}

def createNewLocalSession() {
    def sessinObject = createNewSessionWithSmartCheck()
    echo "Creating local session object"
    smartCheckLocalSession.put("id", "${sessinObject.get('id')}")
    smartCheckLocalSession.put("token", "${sessinObject.get('token')}")
    def now = Calendar.getInstance();
    now.add(Calendar.MINUTE, 55)
    smartCheckLocalSession.put("expiry", now.getTime())
}

def createNewSessionWithSmartCheck() {
    echo "Creating session with smart check api"
    withCredentials([usernamePassword(credentialsId: 'smart-check-jenkins-user', usernameVariable: 'userName', passwordVariable: 'password')]) {
        def authPostBody = """
            {
                "user": {
                    "userID": "${userName}",
                    "password": "${password}"
                }
            }
        """
        // TODO remove ignoreSslErrors once certificates are deployed
        def authResponse = httpRequest ignoreSslErrors: true, acceptType: 'APPLICATION_JSON', contentType: 'APPLICATION_JSON', httpMode: 'POST', requestBody: authPostBody, url: "${SMART_CHECK_HOST_URL}/api/sessions"

        return parseJSON(authResponse.content)
    }
}

def startImageScanFromRegistry(smartCheckRegistryName, repositoryName, imageTag) {
    def token = getSmartCheckToken()
    def postBody = """
    {
        "name": "smart-check-api-scan-${env.JOB_NAME}-${env.BUILD_NUMBER}",
        "source": {
            "repository": "${repositoryName}",
            "tag": "${imageTag}"
        }
    }
    """
    def registryId = getRegistryIdByName(smartCheckRegistryName)
    echo "Initiating scan for registryId: ${registryId}, repositoryName: ${repositoryName} and imageTag: ${imageTag}"
    // TODO remove ignoreSslErrors once certificates are deployed
    def startScanResponse = httpRequest ignoreSslErrors: true, customHeaders: [[name: 'Authorization', value: "Bearer ${token}"]], acceptType: APPLICATION_JSON, contentType: APPLICATION_JSON, httpMode: 'POST', requestBody: postBody, url: "${SMART_CHECK_HOST_URL}/api/registries/${registryId}/scans"

    return parseJSON(startScanResponse.content)
}

def getRegistryIdByName(smartCheckRegistryName) {
    def encodedRegistryName = URLEncoder.encode(smartCheckRegistryName, "UTF-8")
    echo "Fetching registryId for smartCheckRegistryName: ${smartCheckRegistryName}"
    def registry = getRegistryNameRecursively(null, "", smartCheckRegistryName, encodedRegistryName)

    if(registry == null) {
        error("Unable to find registry: ${smartCheckRegistryName}. Please verify the registry name")
    }
    return registry.id
}

def getRegistryNameRecursively(registry, cursor, smartCheckRegistryName, encodedRegistryName) {
    if (registry == null && cursor != null) {
        def cursorQueryParam = cursor ? "&cursor=${cursor}" : ""
        def token = getSmartCheckToken()
        // TODO remove ignoreSslErrors once certificates are deployed
        def getRegistriesResponse = httpRequest ignoreSslErrors: true, customHeaders: [[name: 'Authorization', value: "Bearer ${token}"]], acceptType: APPLICATION_JSON, contentType: APPLICATION_JSON, httpMode: 'GET', url: "${SMART_CHECK_HOST_URL}/api/registries?query=${encodedRegistryName}${cursorQueryParam}"
        def response = parseJSON(getRegistriesResponse.content)
        return getRegistryNameRecursively(response.get("registries").find { it.get("name").equals(smartCheckRegistryName) }, response.get("next"), smartCheckRegistryName, encodedRegistryName)
    }

    return registry
}

def getScanResultById(scanId) {
    def token = getSmartCheckToken()
    // TODO remove ignoreSslErrors once certificates are deployed
    def getScanResponse = httpRequest ignoreSslErrors: true, customHeaders: [[name: 'Authorization', value: "Bearer ${token}"]], acceptType: APPLICATION_JSON, contentType: APPLICATION_JSON, httpMode: 'GET', url: "${SMART_CHECK_HOST_URL}/api/scans/${scanId}?expand=none"
    return parseJSON(getScanResponse.content)
}

def waitForImageScanCompletion(scanId, maxWaitInMins) {
    def success = false;
    counter = maxWaitInMins * 2;
    while (counter > 0) {
        def scanResult = getScanResultById(scanId)
        def scanStatus = scanResult.get("status")
        if(SMART_CHECK_SCAN_WAIT_STATES.contains(scanStatus)) {
            echo "Image scan is in ${scanStatus} state. \nWaiting for updates... (30 Seconds) Time: ${new Date()}"
            sleep time: 30, unit: 'SECONDS'
            counter = counter - 1
        } else {
            success = evaluateImageScanResultStatus(scanResult, scanStatus)
            break;
        }
    }
    if(counter <= 0) {
        echo "Image scan did not complete in ${maxWaitInMins} minutes.\n Consider waiting more time or view the scan details on the dashboard using the link below."
    }

    logStep("Visit scan details: ${SMART_CHECK_HOST_URL}/scans/${scanId}")

    if(!success) {
        currentBuild.setResult("FAILURE")
    }

    return success
}

def evaluateImageScanResultStatus(scanResult, scanStatus) {
    def success = false
    switch (scanStatus) {
        case "completed-with-findings":
            echo "Image scan ${scanStatus}."
            def unresolvedVulnerabilitiesMap = scanResult.get("findings").get("vulnerabilities").get("unresolved")
            if (FAIL_ON_VULNERABILITIES_LIST.disjoint(unresolvedVulnerabilitiesMap.keySet())) {
                success = true
            } else {
                echo "Image contains either/or all of ${FAIL_ON_VULNERABILITIES_LIST} severe vulnerabilities.\nTotal unresolved vulnerabilities: ${unresolvedVulnerabilitiesMap}"
            }
            break;
        case "failed":
            echo "Image scan ${scanStatus}."
            break;
        case "completed-no-findings":
            echo "Image scan ${scanStatus}."
            success = true
            break;
        default:
            echo "Image scan resulted in unknown state: ${scanStatus}.\n Please check the smart check api for updated states"
            break;
        }
    return success
}


@NonCPS
def parseJSON(text) {
    return new groovy.json.JsonSlurperClassic().parseText(text)
}


return this
