# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""Security Incident SOC Environment Client."""

from typing import Dict, Any

from openenv.core import EnvClient
from openenv.core.client_types import StepResult
from openenv.core.env_server.types import State

from .models import Action, Observation


class SecurityIncidentSOCEnv(
    EnvClient[Action, Observation, State]
):
    """
    Client for the Security Incident SOC Environment.

    This client maintains a persistent connection to the environment server,
    enabling efficient multi-step interactions with lower latency.
    Each client instance has its own dedicated environment session on the server.

    Example:
        >>> # Connect to a running server
        >>> with SecurityIncidentSOCEnv(base_url="http://localhost:7860") as client:
        ...     result = client.reset(task="easy_known_malware")
        ...     print(result.observation.alerts)
        ...
        ...     result = client.step(Action(type="investigate_file", target_id="F1"))
        ...     print(result.observation.last_action_result)

    Example with Docker:
        >>> # Automatically start container and connect
        >>> client = SecurityIncidentSOCEnv.from_docker_image("security-incident-soc:latest")
        >>> try:
        ...     result = client.reset(task="easy_known_malware")
        ...     result = client.step(Action(type="quarantine_file", target_id="F1"))
        ... finally:
        ...     client.close()
    """

    def _step_payload(self, action: Action) -> Dict[str, Any]:
        """
        Convert Action to JSON payload for step message.

        Args:
            action: Action instance

        Returns:
            Dictionary representation suitable for JSON encoding
        """
        return {
            "action": action.model_dump(),
        }

    def _parse_result(self, payload: Dict[str, Any]) -> StepResult[Observation]:
        """
        Parse server response into StepResult[Observation].

        Args:
            payload: JSON response data from server

        Returns:
            StepResult with Observation
        """
        obs_data = payload.get("observation", {})
        observation = Observation(
            alerts=obs_data.get("alerts", []),
            file_metadata=obs_data.get("file_metadata", []),
            process_tree=obs_data.get("process_tree", []),
            last_action_result=obs_data.get("last_action_result", ""),
        )

        return StepResult(
            observation=observation,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict[str, Any]) -> State:
        """
        Parse server response into State object.

        Args:
            payload: JSON response from state request

        Returns:
            State object with episode information
        """
        return State(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
        )