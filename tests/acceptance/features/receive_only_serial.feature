Feature: A serial vehicle link is receive-only
  AegisFlight must never transmit on a port that could be wired to a physical flight controller.
  Only pyserial socket:// URLs (loopback SITL) may carry uplink traffic.

  Scenario Outline: Operating-system serial device names are treated as a real vehicle
    When the bridge classifies the port "<port>"
    Then the port may reach a vehicle

    Examples:
      | port           |
      | COM7           |
      | /dev/ttyACM0   |
      | /dev/cu.usbmodem1101 |
      | /dev/pts/4     |

  Scenario Outline: Loopback URLs and non-serial transports are not a vehicle
    When the bridge classifies the port "<port>"
    Then the port may not reach a vehicle

    Examples:
      | port                  |
      | socket://127.0.0.1:5762 |
      | socket://172.30.0.10:5762 |

  Scenario: A transport without a port name is not a vehicle
    When the bridge classifies a transport that has no port
    Then the port may not reach a vehicle

  Scenario: An empty port name is not a vehicle
    When the bridge classifies an empty port name
    Then the port may not reach a vehicle

  Scenario: Active IPS is refused when the vehicle link is a serial device
    When an Active IPS bridge is built on the serial device "/dev/ttyACM0"
    Then building the bridge is refused

  Scenario: A passive bridge on a serial link never originates a frame of its own
    Given a passive inline bridge whose vehicle link is the serial device "/dev/ttyACM0"
    When the vehicle streams telemetry and the ground station stays silent
    Then nothing is written to the vehicle link

  Scenario: Pyserial URL handlers are refused unless explicitly allowed
    When a serial source is opened on "spy:///tmp/x" without allow_url
    Then opening is refused
