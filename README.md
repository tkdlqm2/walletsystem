docker build -t ace-batch .
docker run -p outside:inside ace-batch

0xbA17b965F8c7CaAdF289877D07E973f6Aa36B093
5205fc9910f5c1ff43a896cb48765a32c38b26784045ad34384c9bcb0bcc29f0

docker logs --tail 10 -f  dc8bc0174baf

docker run \
    -v /PATH/TO/.env:/app/.env \
    -it ace-batch "./main"

docker run \
    -v /PATH/TO/.env:/app/cmd/.env \
    ace-batch

docker run ace-batch


docker run -it ace-batch "/bin/bash"


docker container prune : 중지된 모든 컨테이너 삭제
docker image prune : 사용하지 않는 이미지 삭제(dangling images)
docker volume prune : 컨테이너와 연결되지 않은 모든 볼륨 삭제
docker network prune : 컨테이너와 연결되지 않은 모든 네트워크 삭제
docker system prune -a : 위에 명령어를 통합해서 한번에 실행. 사용하지 않는 모든 오브젝트를 삭제