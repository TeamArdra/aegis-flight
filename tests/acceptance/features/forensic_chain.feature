Feature: The forensic log detects tampering, including across rotated segments
  Scenario: An untouched rotated log verifies on every segment
    Given an event store with 5 events that has been rotated and then written to again
    Then every segment's event chain verifies
    And the active segment records the closing hashes of the rotated segment

  Scenario: Editing one event in a rotated segment is detected
    Given an event store with 5 events that has been rotated and then written to again
    When an event in the rotated segment is edited in place
    Then the rotated segment's chain is reported broken
    And the active segment still verifies

  Scenario: Deleting an event from the middle of a segment is detected
    Given an event store with 5 events that has been rotated and then written to again
    When the third event of the rotated segment is deleted
    Then the rotated segment's chain is reported broken

  Scenario: Corrupted stored JSON is reported as a broken chain, never a crash
    Given an event store with 5 events that has been rotated and then written to again
    When the evidence column of the rotated segment holds invalid JSON
    Then the rotated segment's chain is reported broken
