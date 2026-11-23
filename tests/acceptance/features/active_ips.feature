Feature: Active IPS blocks hostile uplink traffic without locking the pilot out
  Scenario: A forged control command is blocked before it reaches the vehicle
    Given an Active IPS policy that trusts only the real ground station
    When an untrusted source sends a mode change
    Then the frame is dropped
    And the drop is counted as untrusted control

  Scenario: Armed-state lock on protected parameters
    Given an Active IPS policy with the semantic firewall enabled
    And the vehicle reports that it is armed
    When the ground station writes the protected parameter "FS_GCS_ENABLE"
    Then the frame is dropped
    And the semantic firewall counts one dropped parameter write

  Scenario: The same write is allowed on the ground
    Given an Active IPS policy with the semantic firewall enabled
    And the vehicle reports that it is disarmed
    When the ground station writes the protected parameter "FS_GCS_ENABLE"
    Then the frame is forwarded

  Scenario: A geofence clear while armed is blocked
    Given an Active IPS policy with the semantic firewall enabled
    And the vehicle reports that it is armed
    When the ground station clears the geofence
    Then the frame is dropped

  Scenario: The local safe-hold override forwards everything and only reports
    Given a signing-aware vehicle filter that has engaged
    When the operator creates the local override file
    And a forged command arrives
    Then the forged command is forwarded
    And the filter state is "override"

  Scenario: Removing the override does not re-engage until the key is proved again
    Given a signing-aware vehicle filter that has engaged
    And the operator created the local override file and then removed it
    When a forged command arrives
    Then the forged command is forwarded
    And the filter state is "learning"
