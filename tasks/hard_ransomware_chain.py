from env.env import SecurityIncidentEnv
from graders.hard_grader import grade

def create_task():
    def env_creator():
        return SecurityIncidentEnv("hard")
    
    return {
        "env_creator": env_creator,
        "grader": grade,
        "max_steps": 8
    }

