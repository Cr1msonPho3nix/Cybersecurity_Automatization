## Scenario

In this lab, you\'re working as a security analyst and your main tasks
are as follows:

-   Extracting device IDs containing certain characters from a log;
    these characters correspond with a certain operating system that
    requires an update.
-   Extracting all IP addresses from a log and then comparing them to
    those that are flagged in a list.
## Task 1

In order to work with regular expressions in Python, start by importing
the `re` module.

``` python
# Import the `re` module in Python

import re
```
## Task 2

In your work as a cybersecurity analyst, you\'re responsible for
updating devices. A device ID that begins with the characters `"r15"`
indicates that the device has a certain operating system that must be
updated.

You\'re given a log of device IDs, stored in a variable named `devices`.
Your eventual goal is to extract the device IDs that start with the
characters `"r15"`. For now, display the contents of the whole string to
examine what it contains.

``` python
# Assign `devices` to a string containing device IDs, each device ID represented by alphanumeric characters

devices = "r262c36 67bv8fy 41j1u2e r151dm4 1270t3o 42dr56i r15xk9h 2j33krk 253be78 ac742a1 r15u9q5 zh86b2l ii286fq 9x482kt 6oa6m6u x3463ac i4l56nq g07h55q 081qc9t r159r1u"

# Display the contents of `devices`

print(devices)
```

## Task 3

In this task, you\'ll write a pattern to find devices that start with
the character combination of `"r15"`.
``` python
# Assign `devices` to a string containing device IDs, each device ID represented by alphanumeric characters

devices = "r262c36 67bv8fy 41j1u2e r151dm4 1270t3o 42dr56i r15xk9h 2j33krk 253be78 ac742a1 r15u9q5 zh86b2l ii286fq 9x482kt 6oa6m6u x3463ac i4l56nq g07h55q 081qc9t r159r1u"

# Assign `target_pattern` to a regular expression pattern for finding device IDs that start with "r15"

target_pattern = "r15\w+"
```
## Task 4

Use the `findall()` function from the `re` module to find the device IDs
that the `target_pattern` matches with.
``` python
# Assign `devices` to a string containing device IDs, each device ID represented by alphanumeric characters

devices = "r262c36 67bv8fy 41j1u2e r151dm4 1270t3o 42dr56i r15xk9h 2j33krk 253be78 ac742a1 r15u9q5 zh86b2l ii286fq 9x482kt 6oa6m6u x3463ac i4l56nq g07h55q 081qc9t r159r1u"

# Assign `target_pattern` to a regular expression pattern for finding device IDs that start with "r15"

target_pattern = "r15\w+"

# Use `re.findall()` to find the device IDs that start with "r15" and display the results

print(re.findall(target_pattern, devices))
```
## Task 5

Now, the next task you\'re responsible for is analyzing a network
security log file and determining which IP addresses have been flagged
for unusual activity.

You\'re given the log file as a string stored in a variable named
`log_file`. There are some invalid IP addresses in the log file due to
issues in data collection. Your eventual goal is to use regular
expressions to extract the valid IP addresses from the string.

Start by displaying the contents of the `log_file` to examine the
details inside.
``` python
# Assign `log_file` to a string containing username, date, login time, and IP address for a series of login attempts

log_file = "eraab 2022-05-10 6:03:41 192.168.152.148 \niuduike 2022-05-09 6:46:40 192.168.22.115 \nsmartell 2022-05-09 19:30:32 192.168.190.178 \narutley 2022-05-12 17:00:59 1923.1689.3.24 \nrjensen 2022-05-11 0:59:26 192.168.213.128 \naestrada 2022-05-09 19:28:12 1924.1680.27.57 \nasundara 2022-05-11 18:38:07 192.168.96.200 \ndkot 2022-05-12 10:52:00 1921.168.1283.75 \nabernard 2022-05-12 23:38:46 19245.168.2345.49 \ncjackson 2022-05-12 19:36:42 192.168.247.153 \njclark 2022-05-10 10:48:02 192.168.174.117 \nalevitsk 2022-05-08 12:09:10 192.16874.1390.176 \njrafael 2022-05-10 22:40:01 192.168.148.115 \nyappiah 2022-05-12 10:37:22 192.168.103.10654 \ndaquino 2022-05-08 7:02:35 192.168.168.144"

# Display contents of `log_file`

print(log_file)
```
## Task 6

In this task, you\'ll build a regular expression pattern that you can
use later on to extract IP addresses that are in the form of
xxx.xxx.xxx.xxx. In other words, you\'ll extract all IP addresses that
contain four segments of three digits that are separated by periods.

Write a regular expression pattern that will match with these IP
addresses and store it in a variable named `pattern`.
``` python
# Assign `log_file` to a string containing username, date, login time, and IP address for a series of login attempts

log_file = "eraab 2022-05-10 6:03:41 192.168.152.148 \niuduike 2022-05-09 6:46:40 192.168.22.115 \nsmartell 2022-05-09 19:30:32 192.168.190.178 \narutley 2022-05-12 17:00:59 1923.1689.3.24 \nrjensen 2022-05-11 0:59:26 192.168.213.128 \naestrada 2022-05-09 19:28:12 1924.1680.27.57 \nasundara 2022-05-11 18:38:07 192.168.96.200 \ndkot 2022-05-12 10:52:00 1921.168.1283.75 \nabernard 2022-05-12 23:38:46 19245.168.2345.49 \ncjackson 2022-05-12 19:36:42 192.168.247.153 \njclark 2022-05-10 10:48:02 192.168.174.117 \nalevitsk 2022-05-08 12:09:10 192.16874.1390.176 \njrafael 2022-05-10 22:40:01 192.168.148.115 \nyappiah 2022-05-12 10:37:22 192.168.103.10654 \ndaquino 2022-05-08 7:02:35 192.168.168.144"

# Assign `pattern` to a regular expression pattern that will match with IP addresses of the form xxx.xxx.xxx.xxx
pattern = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
```
## Task 7

Call the `re.findall()` function with the variables `pattern` and
`log_file` and store the output in a variable named
`valid_ip_addresses`.

Then, display the contents of `valid_ip_addresses` and run the cell to
analyze the results.
``` python
# Assign `log_file` to a string containing username, date, login time, and IP address for a series of login attempts

log_file = "eraab 2022-05-10 6:03:41 192.168.152.148 \niuduike 2022-05-09 6:46:40 192.168.22.115 \nsmartell 2022-05-09 19:30:32 192.168.190.178 \narutley 2022-05-12 17:00:59 1923.1689.3.24 \nrjensen 2022-05-11 0:59:26 192.168.213.128 \naestrada 2022-05-09 19:28:12 1924.1680.27.57 \nasundara 2022-05-11 18:38:07 192.168.96.200 \ndkot 2022-05-12 10:52:00 1921.168.1283.75 \nabernard 2022-05-12 23:38:46 19245.168.2345.49 \ncjackson 2022-05-12 19:36:42 192.168.247.153 \njclark 2022-05-10 10:48:02 192.168.174.117 \nalevitsk 2022-05-08 12:09:10 192.16874.1390.176 \njrafael 2022-05-10 22:40:01 192.168.148.115 \nyappiah 2022-05-12 10:37:22 192.168.103.10654 \ndaquino 2022-05-08 7:02:35 192.168.168.144"

# Assign `pattern` to a regular expression that matches with all valid IP addresses and only those

pattern = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

# Use `re.findall()` on `pattern` and `log_file` and assign `valid_ip_addresses` to the output

valid_ip_addresses = re.findall(pattern, log_file)

# Display the contents of `valid_ip_addresses`

print(valid_ip_addresses)
```
## Task 8

Now, all of the valid IP addresses have been extracted. The next step is
to identify flagged IP addresses.

You\'re given a list of IP addresses that have been previously flagged
for unusual activity, stored in a variable named `flagged_addresses`.
When these addresses are encountered, they should be investigated
further.

Display this list and examine what it contains by running the cell.
``` python
# Assign `flagged_addresses` to a list of IP addresses that have been previously flagged for unusual activity

flagged_addresses = ["192.168.190.178", "192.168.96.200", "192.168.174.117", "192.168.168.144"]

# Display the contents of `flagged_addresses`

print(flagged_addresses)
```
## Task 9

Write an iterative statement that loops through the `valid_ip_addresses`
list and checks if each IP address is flagged. Include a conditional
that checks if the `address` belongs to the `flagged_addresses` list.

-   If so, it should display
    `"The IP address ______ has been flagged and requires further analysis."`
-   If not, it should display
    `"The IP address ______ requires no analysis."`
``` python
# Assign `log_file` to a string containing username, date, login time, and IP address for a series of login attempts

log_file = "eraab 2022-05-10 6:03:41 192.168.152.148 \niuduike 2022-05-09 6:46:40 192.168.22.115 \nsmartell 2022-05-09 19:30:32 192.168.190.178 \narutley 2022-05-12 17:00:59 1923.1689.3.24 \nrjensen 2022-05-11 0:59:26 192.168.213.128 \naestrada 2022-05-09 19:28:12 1924.1680.27.57 \nasundara 2022-05-11 18:38:07 192.168.96.200 \ndkot 2022-05-12 10:52:00 1921.168.1283.75 \nabernard 2022-05-12 23:38:46 19245.168.2345.49 \ncjackson 2022-05-12 19:36:42 192.168.247.153 \njclark 2022-05-10 10:48:02 192.168.174.117 \nalevitsk 2022-05-08 12:09:10 192.16874.1390.176 \njrafael 2022-05-10 22:40:01 192.168.148.115 \nyappiah 2022-05-12 10:37:22 192.168.103.10654 \ndaquino 2022-05-08 7:02:35 192.168.168.144"

# Assign `pattern` to a regular expression that matches with all valid IP addresses and only those

pattern = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

# Use `re.findall()` on `pattern` and `log_file` and assign `valid_ip_addresses` to the output

valid_ip_addresses = re.findall(pattern, log_file)

# Assign `flagged_addresses` to a list of IP addresses that have been previously flagged for unusual activity

flagged_addresses = ["192.168.190.178", "192.168.96.200", "192.168.174.117", "192.168.168.144"]

# Loop through `valid_ip_addresses` with `address` as the loop variable

for address in valid_ip_addresses:
    if address in flagged_addresses:
        print("The IP address", address, "has been flagged and requires further analysis.")

    # Otherwise, display "The IP address ______ does not require further analysis."

    else:
        print("The IP address", address, "requires no analysis.")
```
## Summary
-   Regular expressions in Python allow you to create patterns that you
    can then use to find important strings.
-   Regular expression patterns can be built to match specific
    characters and character combinations.
-   Examples of regular expression symbols practiced in this lab:
    -   `\w` represents any alphanumeric character.
    -   `+` represents one or more occurrences of the previous character
        in the regular expression.
    -   `\d` represents any digit.
    -   `\.` represents a period.
    -   `{x,y}` represents anywhere between x and y number of
        occurrences of the previous character in the regular expression.
        The x and y can be replaced with any two positive integers to
        indicate an exact range for the number of occurrences.
-   The `re` module in Python contains functions that are useful when
    working with regular expressions.
    -   One example is the `re.findall()` function, which takes in a
        regular expression pattern as well as a string, checks for all
        instances in the string that match with the pattern and outputs
        a list of the matches.