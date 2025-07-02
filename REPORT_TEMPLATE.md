# Отчёт по практике: Анализ системных вызовов с eBPF

## ФИО:

Куликова Алёна Владимировна

## Группа:

КБ-9

## Дата:

02.07.2025

## 1. Общая картина

1. что делает каждый контейнер?

Spring Boot - фреймворк для создания приложений на Java

Docker - используется для контейнеризации приложения

2. Есть ли признаки атаки? Бонус: если да, то какая CVE?

![image](https://github.com/user-attachments/assets/12ace17e-fd6e-4e1d-a5a7-1c4ae463ff7e)

Запрос выглядит как стандартный HTTP-запрос для получения информации с сервера и не содержит явных признаков злонамеренных действий. Возможно атака Remote Code Execution

![image](https://github.com/user-attachments/assets/8cf8ed08-9cc7-4649-8111-f406d8bdef19)

Запрос GET /shell.jsp?cmd=id вызывает подозрения, так как он включает в себя параметр cmd=id. Данный запрос похож на попытку выполнения удаленной команды через веб-интерфейс

3. Что указывает на отклонения от нормы?

достаточно интересно, что происходит при /app/exploit.py, который пользователь трогает

4. Какие инструменты были полезны?

все инструменты дают возможность проанализировать ситуацию со всех сторон

---

## 2. Работа

Так как команда ``` docker compose up -d ``` никак не хотела работать, так как появилась беда с tomcat, был переписан docker-compose.yml (находится тут: https://github.com/Kulikova-A18/docker_prac/blob/main/docker-compose.yml):

```
version: '3.8'

...

  tomcat:
    image: tomcat:9.0
    container_name: tomcat
    ports:
      - "8081:8080"
    networks:
      fixed_net:
        ipv4_address: 10.10.0.4
    logging:
      driver: syslog
      options:
        syslog-facility: "local0"
        tag: "docker-tomcat"
```

Было в работе взят код Анализ системных вызовов с eBPF с https://github.com/Kulikova-A18/ebpf_prac/tree/main

Сам результат располагается тут: https://github.com/Kulikova-A18/docker_prac/blob/main/syscall_trace.log

интересное замечание 

![image](https://github.com/user-attachments/assets/c0343b1f-c1ed-4f33-88db-a2640c5403bb)

Также был написан код на питоне. Краткое описание кода https://github.com/Kulikova-A18/docker_prac/blob/main/main.py

| Функция                | Описание                                                                                                           |
|------------------------|--------------------------------------------------------------------------------------------------------------------|
| check_utilities()    | Проверяет наличие утилит docker, tcpdump и bpftrace |
| run_docker_compose() | Запускает docker-compose с флагом up -d, чтобы поднять контейнеры в фоновом режиме |
| get_container_ids()  | Получает идентификаторы запущенных Docker-контейнеров, используя команду docker ps |
| capture_traffic()    | Запускает tcpdump для захвата сетевого трафика и сохранения его в файл network_traffic.pcap |
| get_logs(container_id) | Получает логи указанного контейнера и записывает их в файл activity_log.csv |
| loading_indicator(duration) | Отображает индикатор загрузки в течение указанного времени (в секундах) |
| main()               | Основная функция, которая вызывает другие функции: проверяет утилиты, запускает Docker Compose, получает идентификаторы контейнеров, запускает потоки для захвата трафика и получения логов, а также отображает индикатор загрузки |

activity_log.csv: https://github.com/Kulikova-A18/docker_prac/blob/main/activity_log.csv

![image](https://github.com/user-attachments/assets/f017dbde-a392-4d02-94f9-fdb23fe6eeb8)

network_traffic.pcap: https://github.com/Kulikova-A18/docker_prac/blob/main/network_traffic.pcap

Введем команду ``` sudo docker ps -a ```

```
vboxuser@xubu:~/docker_prac$ sudo docker ps -a
CONTAINER ID   IMAGE                      COMMAND                CREATED             STATUS          PORTS                                         NAMES
885da260a6f1   docker_prac-client         "bash entrypoint.sh"   About an hour ago   Up 47 minutes                                                 client
7e30a80e457f   docker_prac-spring4shell   "catalina.sh run"      About an hour ago   Up 44 minutes   0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp   spring
fb74d9e0af3a   tomcat:9.0                 "catalina.sh run"      About an hour ago   Up 44 minutes   0.0.0.0:8081->8080/tcp, [::]:8081->8080/tcp   tomcat

```

Так же проверим и ведем команду ``` sudo docker inspect docker_prac-spring4shell ```

```
vboxuser@xubu:~/docker_prac$ sudo docker inspect docker_prac-spring4shell
[
    {
        "Id": "sha256:9fb92d9fd9f05130cd195b26bdfc4d5f6859841455b1a5bf188b56e4115c1af9",
        "RepoTags": [
            "docker_prac-spring4shell:latest"
        ],
        "RepoDigests": [],
        "Parent": "",
        "Comment": "buildkit.dockerfile.v0",
        "Created": "2025-07-02T21:04:02.805324297+03:00",
        "DockerVersion": "",
        "Author": "",
        "Config": {
            "Hostname": "",
            "Domainname": "",
            "User": "",
            "AttachStdin": false,
            "AttachStdout": false,
            "AttachStderr": false,
            "ExposedPorts": {
                "8080/tcp": {}
            },
            "Tty": false,
            "OpenStdin": false,
            "StdinOnce": false,
            "Env": [
                "PATH=/usr/local/tomcat/bin:/usr/local/openjdk-11/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "JAVA_HOME=/usr/local/openjdk-11",
                "LANG=C.UTF-8",
                "JAVA_VERSION=11.0.14.1",
                "CATALINA_HOME=/usr/local/tomcat",
                "TOMCAT_NATIVE_LIBDIR=/usr/local/tomcat/native-jni-lib",
                "LD_LIBRARY_PATH=/usr/local/tomcat/native-jni-lib",
                "GPG_KEYS=48F8E69F6390C9F25CFEDCD268248959359E722B A9C5DF4D22E99998D9875A5110C01C5A2F6059E7 DCFD35E0BF8CA7344752DE8B6FB21E8933C60243",
                "TOMCAT_MAJOR=9",
                "TOMCAT_VERSION=9.0.59",
                "TOMCAT_SHA512=74902b522abda04afb2be24d7410d4d93966d20fd07dde8f03bb281cdc714866f648babe1ff1ae85d663774779235f1cb9d701d5ce8884052f1f5efca7b62c68"
            ],
            "Cmd": [
                "catalina.sh",
                "run"
            ],
            "ArgsEscaped": true,
            "Image": "",
            "Volumes": null,
            "WorkingDir": "/helloworld/",
            "Entrypoint": null,
            "OnBuild": null,
            "Labels": {
                "com.docker.compose.project": "docker_prac",
                "com.docker.compose.service": "spring4shell",
                "com.docker.compose.version": "2.33.1"
            }
        },
        "Architecture": "amd64",
        "Os": "linux",
        "Size": 1099072681,
        "GraphDriver": {
            "Data": {
                "LowerDir": "/var/snap/docker/common/var-lib-docker/overlay2/6vkhuwujxlzkdzsht8khw4jhc/diff:/var/snap/docker/common/var-lib-docker/overlay2/bng9sdqz42a9m8c06ox4ao9ew/diff:/var/snap/docker/common/var-lib-docker/overlay2/zosvyw0834djuewq35fquextk/diff:/var/snap/docker/common/var-lib-docker/overlay2/a2in1429ijfcwewini2r0ra9e/diff:/var/snap/docker/common/var-lib-docker/overlay2/ghuy5g0gsbyrtzm3msrmvb1py/diff:/var/snap/docker/common/var-lib-docker/overlay2/87f9341228a2304ebf28c07c142ca19157efd6ec643494708c3d018c8329d3a6/diff:/var/snap/docker/common/var-lib-docker/overlay2/73df683e7c16a8dc64eb76f6588669e9b33f44ca604f6e4061853d3acd48a9ee/diff:/var/snap/docker/common/var-lib-docker/overlay2/e897c0ab28ec57edac4b59c384602ef3238dedb2dbb12c49c15960f1480a3919/diff:/var/snap/docker/common/var-lib-docker/overlay2/128742b9b961e81ff51ac8108e3e7c301a4bf3ddfe875929e3315b66df40cc61/diff:/var/snap/docker/common/var-lib-docker/overlay2/8cfbad36b7de6b1a5902c2db46d446d9f6a87267b1b7e5d28a449e9bb7b71430/diff:/var/snap/docker/common/var-lib-docker/overlay2/a888e693a37736b3e7fc628379b00175e7eec750235d091c97a721b773b17a31/diff:/var/snap/docker/common/var-lib-docker/overlay2/8d07037c310c6edcd28466a1d51dc18fb2fce129704f96e9c34884da5716d16b/diff:/var/snap/docker/common/var-lib-docker/overlay2/b32512c55e50ba32164790f4c1266d72f187b10d82cf1aa9699847e8a2c5cc19/diff:/var/snap/docker/common/var-lib-docker/overlay2/ef6d6a75cd431fdbfd899f22ff4c5cfd1f096409d1bc70fcb6c77731ac6a77da/diff:/var/snap/docker/common/var-lib-docker/overlay2/45a095c9459a9ccb9e5a499026069439c1b491b42ea3641783eb2d8b7b872b8e/diff",
                "MergedDir": "/var/snap/docker/common/var-lib-docker/overlay2/j475rdpg1qx48838jt1vb7wwp/merged",
                "UpperDir": "/var/snap/docker/common/var-lib-docker/overlay2/j475rdpg1qx48838jt1vb7wwp/diff",
                "WorkDir": "/var/snap/docker/common/var-lib-docker/overlay2/j475rdpg1qx48838jt1vb7wwp/work"
            },
            "Name": "overlay2"
        },
        "RootFS": {
            "Type": "layers",
            "Layers": [
                "sha256:89fda00479fc0fe3bf2c411d92432001870e9dad42ddd0c53715ab77ac4f2a97",
                "sha256:26d5108b2cba762ee9b91c30670091458a0c32b02132620b7f844085af596e22",
                "sha256:48144a6f44ae89c578bd705dba2ebdb2a086b36215affa5659b854308fa22e4b",
                "sha256:e3f84a8cee1f3e6a38a463251eb05b87a444dec565a7331217c145e9ef4dd192",
                "sha256:d1609e012401924c7b64459163fd47033dbec7df2eacddbf190d42d934737598",
                "sha256:804bc49f369a8842a9d438142eafc5dcc8fa8e5489596920e1ae6882a9fc9a26",
                "sha256:da814db69f74ac380d1443168b969a07ac8f16c7c4a3175c86a48482a5c7b25f",
                "sha256:e72ea1ea48e9f8399d034213c46456d86efe52e7106d99310143ba705ad8d4ee",
                "sha256:21fb6de0b43a238f95ea6e2f6df2e2d358bdd779ef43e6d85528b47afd715148",
                "sha256:b05616fffe109417a34bbeccc699de5f7815c36e755f5c27ac424654f98bb203",
                "sha256:5dbcdd0b3a9fc0952fb0937dc7cb3b93fba5e3f9d54777f2dc1dbae35597b5c8",
                "sha256:17b2445565891b32c23a213728d3e7633c20d23f922d83471dee1a7cc38a37fe",
                "sha256:6304495856075acca113a09a4a73d678b6f6aeb67e27e3ca9a45a6c92ec84e37",
                "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
                "sha256:7c6c7cad0347841310c872916becccc7a9dcc7e4a8110d154cecf7b66eeb3788",
                "sha256:8a6aade4ccbde04502dd24e56526c109a8031d590120323b143e9db372a3c4f1"
            ]
        },
        "Metadata": {
            "LastTagTime": "2025-07-02T21:04:03.565537881+03:00"
        }
    }
]
```

Так же проверим и ведем команду ``` sudo docker inspect docker_prac-client ```

```
vboxuser@xubu:~/docker_prac$ sudo docker inspect docker_prac-client
[
    {
        "Id": "sha256:82cd57e88e3ca6219c67a711a0c3db76e17eebf6f44beda085229967fda84919",
        "RepoTags": [
            "docker_prac-client:latest"
        ],
        "RepoDigests": [],
        "Parent": "",
        "Comment": "buildkit.dockerfile.v0",
        "Created": "2025-07-02T21:04:49.609664376+03:00",
        "DockerVersion": "",
        "Author": "",
        "Config": {
            "Hostname": "",
            "Domainname": "",
            "User": "",
            "AttachStdin": false,
            "AttachStdout": false,
            "AttachStderr": false,
            "Tty": false,
            "OpenStdin": false,
            "StdinOnce": false,
            "Env": [
                "PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG=C.UTF-8",
                "GPG_KEY=A035C8C19219BA821ECEA86B64E628F8D684696D",
                "PYTHON_VERSION=3.11.13",
                "PYTHON_SHA256=8fb5f9fbc7609fa822cb31549884575db7fd9657cbffb89510b5d7975963a83a"
            ],
            "Cmd": [
                "bash",
                "entrypoint.sh"
            ],
            "ArgsEscaped": true,
            "Image": "",
            "Volumes": null,
            "WorkingDir": "/app",
            "Entrypoint": null,
            "OnBuild": null,
            "Labels": {
                "com.docker.compose.project": "docker_prac",
                "com.docker.compose.service": "client",
                "com.docker.compose.version": "2.33.1"
            }
        },
        "Architecture": "amd64",
        "Os": "linux",
        "Size": 169121526,
        "GraphDriver": {
            "Data": {
                "LowerDir": "/var/snap/docker/common/var-lib-docker/overlay2/nztou2upcw6zmpkjugwi7rrz3/diff:/var/snap/docker/common/var-lib-docker/overlay2/mo6mt0y418pr2h69cisjg6m43/diff:/var/snap/docker/common/var-lib-docker/overlay2/99w2uw9005s9dqjd0homluqkl/diff:/var/snap/docker/common/var-lib-docker/overlay2/bk4peakvt03qp8teq5eyntsag/diff:/var/snap/docker/common/var-lib-docker/overlay2/0v7v5vedj6tv6ksm7wjyq34mw/diff:/var/snap/docker/common/var-lib-docker/overlay2/87379ba4ac791fb56c404833b41f47cee6174741d5b7ab75619eb14b8ef0fd88/diff:/var/snap/docker/common/var-lib-docker/overlay2/f881eaa302fee6c512abab1f390b70320f948ffcaa888ceda83b9b92a4c5783c/diff:/var/snap/docker/common/var-lib-docker/overlay2/4242b074bb0970f351ec556a08eb6568bbebd4b8285044d8658bf84e768e224e/diff:/var/snap/docker/common/var-lib-docker/overlay2/450faf7876ac8765a8cb7d9d7634cb8d8b92138b3c1f3a4f856631133bce3815/diff",
                "MergedDir": "/var/snap/docker/common/var-lib-docker/overlay2/jq3lj31mc2keoeeh5sqtvrrfy/merged",
                "UpperDir": "/var/snap/docker/common/var-lib-docker/overlay2/jq3lj31mc2keoeeh5sqtvrrfy/diff",
                "WorkDir": "/var/snap/docker/common/var-lib-docker/overlay2/jq3lj31mc2keoeeh5sqtvrrfy/work"
            },
            "Name": "overlay2"
        },
        "RootFS": {
            "Type": "layers",
            "Layers": [
                "sha256:1bb35e8b4de116e84b2ccf614cce4e309b6043bf2cd35543d8394edeaeb587e3",
                "sha256:e5b65e4c6bdaf3c7cadef19ac743fd2794a55263b1a8a5223d1ce80db17f80fc",
                "sha256:a1061f722fb28743b069a30196d9a7c3d5b16d0d3532c67fdb168040acdd6a2e",
                "sha256:546c6f4e2f2c0dedf57fb1aab386b3ab3e23207e24de31966bb7b25d83f315ce",
                "sha256:1dcbed107fba87d1bc94338af3b7bed4ff356f01a19fadfa4c029d53e49f0b81",
                "sha256:b3863db1bc66135d6b1cc38dd6749e19a3f348fc6b314de92ef9589f9cb24ee7",
                "sha256:eb13bd9d46af9b8da132bbfbe782031fc98d3251afa73b2f3448f3cd12e37efd",
                "sha256:13f7d97d81f8db95a538459aa02974b41156003d7f3ed9e3a64a22bcc18a9bda",
                "sha256:b188c2624dbcaadcdeb95ac4c12cb53515bee961f13fa43a3389caa739066d81",
                "sha256:d6513bb87f3920374e9c477a9b6ef48bfb5a7acf6ecb5af90408fc49975e72b5"
            ]
        },
        "Metadata": {
            "LastTagTime": "2025-07-02T21:04:49.712964931+03:00"
        }
    }
]

```

Так же проверим и ведем команду ``` sudo docker inspect tomcat:9.0 ```

```
vboxuser@xubu:~/docker_prac$ sudo docker inspect tomcat:9.0
[
    {
        "Id": "sha256:9772625c29360862baa89c450683b68d4bc695240358d05f1048e6c474b0a07b",
        "RepoTags": [
            "tomcat:9.0"
        ],
        "RepoDigests": [
            "tomcat@sha256:850a935a3d7d7c0e635fe495d31bea0c8d986c9fedad227db3a21568d4c3c211"
        ],
        "Parent": "",
        "Comment": "buildkit.dockerfile.v0",
        "Created": "2025-06-10T08:03:44Z",
        "DockerVersion": "",
        "Author": "",
        "Config": {
            "Hostname": "",
            "Domainname": "",
            "User": "",
            "AttachStdin": false,
            "AttachStdout": false,
            "AttachStderr": false,
            "ExposedPorts": {
                "8080/tcp": {}
            },
            "Tty": false,
            "OpenStdin": false,
            "StdinOnce": false,
            "Env": [
                "PATH=/usr/local/tomcat/bin:/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "JAVA_HOME=/opt/java/openjdk",
                "LANG=en_US.UTF-8",
                "LANGUAGE=en_US:en",
                "LC_ALL=en_US.UTF-8",
                "JAVA_VERSION=jdk-21.0.7+6",
                "CATALINA_HOME=/usr/local/tomcat",
                "TOMCAT_NATIVE_LIBDIR=/usr/local/tomcat/native-jni-lib",
                "LD_LIBRARY_PATH=/usr/local/tomcat/native-jni-lib",
                "TOMCAT_MAJOR=9",
                "TOMCAT_VERSION=9.0.106",
                "TOMCAT_SHA512=0b316af119fd9a69761c20bc7f9959513884002fc60f490af6335380a3a62549777bf35a1e8dd3c448e56da8ddcb9dc2301d3b01bba304537ca40456c650c25a"
            ],
            "Cmd": [
                "catalina.sh",
                "run"
            ],
            "Image": "",
            "Volumes": null,
            "WorkingDir": "/usr/local/tomcat",
            "Entrypoint": null,
            "OnBuild": null,
            "Labels": {
                "org.opencontainers.image.ref.name": "ubuntu",
                "org.opencontainers.image.version": "24.04"
            }
        },
        "Architecture": "amd64",
        "Os": "linux",
        "Size": 469278307,
        "GraphDriver": {
            "Data": {
                "LowerDir": "/var/snap/docker/common/var-lib-docker/overlay2/15c9b2426cc868f3f7a6f8724c03a4bbe4e003f30ac1ee3611f865613eed1b45/diff:/var/snap/docker/common/var-lib-docker/overlay2/fb171255bb00f58271ec371224ab1b472ddaacd7ea38deac140d9f4861f62ef0/diff:/var/snap/docker/common/var-lib-docker/overlay2/70a74d22ff5287c506e3d748e28eb347aafbe505cd4ab80b615df4ebeef40cc4/diff:/var/snap/docker/common/var-lib-docker/overlay2/3ce6e96598a4b3ba8d03d270ac0bd426ac94a0d47377a3825a885818173185bd/diff:/var/snap/docker/common/var-lib-docker/overlay2/9b4469286ca910e569902de956b3b4b06cb21e5c9c44d095effb5a10a87ed91b/diff:/var/snap/docker/common/var-lib-docker/overlay2/2360dcacd4cf3952d1e04152d1355a89f1bfcd62e6a815bcd0391d4484083f3b/diff:/var/snap/docker/common/var-lib-docker/overlay2/71e52db477620fa6344789a6a96cd7412dc28bd5d30f914ddbb6b71a192a6ee4/diff:/var/snap/docker/common/var-lib-docker/overlay2/7b53fe9166df71842118ff2007585137ad299140eedff6072597ebb381a16152/diff",
                "MergedDir": "/var/snap/docker/common/var-lib-docker/overlay2/0ab15e31167d5daffff846b8745ca6401127487e978acde3d59fd7551f4af954/merged",
                "UpperDir": "/var/snap/docker/common/var-lib-docker/overlay2/0ab15e31167d5daffff846b8745ca6401127487e978acde3d59fd7551f4af954/diff",
                "WorkDir": "/var/snap/docker/common/var-lib-docker/overlay2/0ab15e31167d5daffff846b8745ca6401127487e978acde3d59fd7551f4af954/work"
            },
            "Name": "overlay2"
        },
        "RootFS": {
            "Type": "layers",
            "Layers": [
                "sha256:45a01f98e78ce09e335b30d7a3080eecab7f50dfa0b38ca44a9dee2654ac0530",
                "sha256:4d8cb8462bc9277a9622c4be8445418296645568d007bfaff8707e665d0957fd",
                "sha256:78635f3af26bd4ae00a280fc0c807cb4d13cbf91a86ee58fdfc4a33b5260bad9",
                "sha256:37d26a060906c9dd89141fe2258a47ed789328f7fd992222c6e52cd5f7456be5",
                "sha256:9574addb83576bcf78d05e10dd6a499a0d3037f5da714648f643a6f11fc5c771",
                "sha256:d4aad42a421cbd7b8e591685445e42de08e4e3aa9a857ed58ebe4e7b1b1ef002",
                "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
                "sha256:10f81df90cc68f20c6bc51ca0c8bbc93dcb06e252e94378cbf79521632456062",
                "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"
            ]
        },
        "Metadata": {
            "LastTagTime": "0001-01-01T00:00:00Z"
        }
    }
]
```

---

## 3. Лог.

Сам файл располагается тут: https://github.com/Kulikova-A18/docker_prac/blob/main/activity_log.csv

Скриншоты, что записалось

![image](https://github.com/user-attachments/assets/adf8d211-8f53-47a6-a2bf-45ecb265f7d9)

![image](https://github.com/user-attachments/assets/f8341326-ff26-427f-a0b3-b3c10a301d6d)
