from env.env import SecurityIncidentEnv
from graders.medium_grader import grade

def create_task():
    def env_creator():
        return SecurityIncidentEnv("medium")
    
    return {
        "env_creator": env_creator,
        "grader": grade,
        "max_steps": 8
    }

