

// Parameters
// CI_PIPELINES_REPOSITORY
// CI_PIPELINES_REPOSITORY_BRANCH
// SOURCE_REPOSITORY
// SOURCE_REPOSITORY_BRANCH
// ECR_HOST
// ECR_REPO_NAME
// AWS_REGION
// ECS_CREDS
// ENVIRONMENT
// CLUSTER_NAME
// SERVICE_NAME
// IMAGE_TAG
// CPU
// MEMORY
// PORT_MAPPINGS
// DISABLE_ROLLBACK
// CONTAINER_DEFINITION_NAME
// TASK_DEFINITION_FAMILY
// LOG_GROUP
// LOG_PREFIX

def commons = null


def runScript() {

    node ("jenkins-ecs-slave-base") {
        def artifactVersion
        def dockerImage
        def containerName
        String currentTaskArn
        String newTaskArn
        String updateServiceStr
        
        try {
            //commons.notifyBuildStart()
            stage ('Setup') {
                commons.cleanWs()
                commons.createDir("tmp")
                commons.setAWSRegion(AWS_REGION)
            }
            stage ('Prepare Deployment') {
                currentTaskArn = commons.getCurrentTaskArn(ECS_CREDS, CLUSTER_NAME, SERVICE_NAME)

                if(IMAGE_TAG?.trim()) {
                	// If the parameter IMAGE_TAG is set then the image used for deployemnt is different, this will create new new Task Definition
                    portMappingsArrayString = commons.convertPortMappingToJSONArrayString(PORT_MAPPINGS)
                    fileContent = createUpdatedTaskDef(portMappingsArrayString)
                    
                    // Write updated task definition to file
                    writeFile file: "tmp/${ENVIRONMENT}-service-task.json", text: fileContent
                    sh "cat tmp/${ENVIRONMENT}-service-task.json"
                    
                    // Register new task definition
                    newTaskArn = commons.registerTaskDefinition(ECS_CREDS, "file://tmp/${ENVIRONMENT}-service-task.json")
                    updateServiceStr = " --task-definition "+ newTaskArn
				}
				else
				{
                	// Else Force deployment of the previous Task Def itself.
    				updateServiceStr = " --force-new-deployment "
				}
            }

            lock("${JOB_NAME} Deploy Service") {
                milestone()
                stage ('Deploy Service') {
                commons.runAWSCmd(params.ECS_CREDS, false, false, """aws ecs update-service \
                    --service ${params.SERVICE_NAME} \
                    --cluster ${params.CLUSTER_NAME} \
                    ${updateServiceStr}""")
                    deploymentID = commons.getDeploymentID(params.ECS_CREDS, params.SERVICE_NAME, params.CLUSTER_NAME)
                    taskArn = (IMAGE_TAG?.trim()) ? newTaskArn : currentTaskArn 
		            echo "Waiting for (5 Minutes) before starting to check for Deployment Status. Current Time: ${new Date()} "
		            sleep time: 5, unit: 'MINUTES'
                    success = commons.waitForEcsDeployment(params.ECS_CREDS, params.SERVICE_NAME, params.CLUSTER_NAME)
                    if (!success) {
                        commons.logStep("Deployment of Service: ${params.SERVICE_NAME} taskDefinition: ${taskArn} was not successful")
                        //commons.notifyBuildFailure()
                        currentBuild.setResult("UNSTABLE")
                    }
                }
            }
            if (!success && (IMAGE_TAG?.trim()) && !params.DISABLE_ROLLBACK) {
                lock("${JOB_NAME} Rollback") {
                    milestone()
                    stage ('Rollback') {
                        commons.logStep("Triggering Rollback")
                        commons.runAWSCmd(params.ECS_CREDS, false, false, """aws ecs update-service \
                        --service ${params.SERVICE_NAME} \
                        --cluster ${params.CLUSTER_NAME} \
                        --task-definition ${currentTaskArn}""")
                        deploymentID = commons.getDeploymentID(params.ECS_CREDS, params.SERVICE_NAME, params.CLUSTER_NAME)
			            echo "Waiting for (5 Minutes) before starting to check for Deployment Status. Current Time: ${new Date()} "
			            sleep time: 5, unit: 'MINUTES'
                        rollbackSuccess = commons.waitForEcsDeployment(params.ECS_CREDS, params.SERVICE_NAME, params.CLUSTER_NAME)
                        if (!rollbackSuccess) {
                            commons.logStep("Rollback of Service: ${params.SERVICE_NAME} taskDefinition: ${currentTaskArn} was not successful")
                            //commons.notifyBuildFailure()
                            currentBuild.setResult("FAILURE")
                        }
                    }
                }
            }
        } 
        catch (error) {
            if (containerName) {
                commons.removeContainerFromNode(containerName)
            }
            //commons.notifyBuildFailure()
            
            throw error
        }
        finally {
            deleteDir()
            //commons.notifyBuild()
        }
    }
}

def createUpdatedTaskDef(portMappings) {
	
    fileContent = """{
        "containerDefinitions": [
            {
                "name": "${CONTAINER_DEFINITION_NAME}",
                "image": "${ECR_HOST}/${ECR_REPO_NAME}:${IMAGE_TAG}",
                "cpu": ${CPU},
                "memory": ${MEMORY},
                "essential": true,
                "portMappings": ${portMappings},
                "environment": [
                    {
                        "name": "SAL_ENV",
                        "value": "${ENVIRONMENT}"
                    }
                ],
                 "logConfiguration": {
			        "logDriver": "awslogs",
			        "options": {
			          "awslogs-group": "${LOG_GROUP}",
			          "awslogs-region": "${AWS_REGION}",
			          "awslogs-stream-prefix": "${LOG_PREFIX}"
			        }
		        },
                "mountPoints": []
            }
        ],
        "volumes": [],
        "family": "${TASK_DEFINITION_FAMILY}"
    }"""

    return fileContent
}


return this


