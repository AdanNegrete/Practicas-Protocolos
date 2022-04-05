//Librerias Comunes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//Librerias socket
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
//Librerias extra
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>

#define TAM_BUFF 	65536

void *packet_Analize(void *arg);
void general_Report();

int pxproto[7]={0,0,0,0,0,0,0};
int pxlont[5]={0,0,0,0,0};
int contador, tot_paq;

int main(int argc, char *argv[]){
	
	char *adaptador;
	char *paq2anz;
	
	int len_addr;
	int len_buff;
	int sockfd;
	unsigned char buffer[TAM_BUFF];  
	pthread_t analizador;
	struct sockaddr saddr;
	
	if (argc < 2) {
		printf ("El argumento debe contener 2 valores\nEjemplo: ./programa num_paquetes adaptador\n");
		exit (1);
	}
	
	adaptador = argv[1];
	paq2anz = argv[2];
	
	contador=atoi(paq2anz);
	tot_paq=atoi(paq2anz);
	
	len_addr=sizeof(saddr);
	
	
	sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(sockfd == -1){	
		fprintf(stderr, "[Error]: No es posible abrir el socket. %d: %s \n",errno, strerror(errno));
		return -1;
	}else{
		printf("[Sistema]: Socket abierto con éxito\n");
	}
	
	struct ifreq iphreq;
	strncpy(iphreq.ifr_name,adaptador,IFNAMSIZ);
	ioctl(sockfd,SIOCGIFFLAGS,&iphreq);
	iphreq.ifr_flags |= IFF_PROMISC;
	if(ioctl(sockfd,SIOCSIFFLAGS,&iphreq)<0){
		printf("\n[Error]: Adaptador no configurado\n");
		return -1;
	}else{
		printf("\n[Sistema]: Adaptador configurado en modo promiscuo\n");
	}
	
	while(contador>0){
		
		memset(&buffer,0, sizeof(buffer));
		memset(&saddr,0, sizeof(saddr));
		
		len_buff=recvfrom(sockfd, buffer, TAM_BUFF, 0,&saddr, (socklen_t*)&len_addr);
		
		if(len_buff == 0)
			printf("\n[Error]: No se recibió mensaje \n");
		
		if(len_buff < 0){
			fprintf(stderr, "[Error]: Mensaje no leído. %d: %s \n",errno, strerror(errno));
		}else{
	
			if(pthread_create(&analizador,NULL,packet_Analize,(void *)&buffer)){
				printf("[Error]: No pudo crearse el hilo\n");
				exit(EXIT_FAILURE);
			}
			
			if(pthread_join(analizador,NULL)){
				printf("[Error]: No pse pudo conectar al hilo\n");
				exit(EXIT_FAILURE);
			}else{
				printf("Paquete %i analizado!!!\n",tot_paq-contador+1);
			}
			
		}
			
	}
	
	general_Report();
	
	char salida[100]="";
	
	strcat(salida,"/sbin/ifconfig ");
	strcat(salida,adaptador);
	strcat(salida," -promisc");
	
	system(salida);
	
}

void *packet_Analize(void *arg){
	
	unsigned char tram_tip[2];
	unsigned char *buff_data=(unsigned char *)arg;
	__be16 pro_tip;
	
	struct sockaddr_in ip_src,ip_dest;
	struct ethhdr *ether;
	struct iphdr *ip_head;
	
	FILE *arch;
	
	ether=(struct ethhdr*)buff_data;
	ip_head=(struct iphdr*)(buff_data + sizeof(struct ethhdr));
	
	memset(&tram_tip,0, sizeof(tram_tip));
	
	arch=fopen("Paquetes.txt","a+");
	
	if(arch==NULL){
		arch=fopen("Paquetes.txt","w");
		fclose(arch);
		arch=fopen("Paquetes.txt","a+");
	}
	
	tram_tip[0]=ether->h_proto>>8;
	tram_tip[1]=ether->h_proto;
	pro_tip=tram_tip[1]<<8;
	pro_tip=pro_tip^tram_tip[0];
	
	if(pro_tip!=0X0800){
		
		switch(pro_tip){
			case 0X86DD:
				fprintf(arch,"~~~~~Paquete descartado, trama tipo IPv6~~~~~\n");
			break;
			case 0X0806:
				fprintf(arch,"~~~~~Paquete descartado, trama tipo ARPA~~~~~\n");
			break;
			case 0X8808:
				fprintf(arch,"~~~~~Paquete descartado, trama de Control de Flujo~~~~~\n");
			break;
			case 0X88E5:
				fprintf(arch,"~~~~~Paquete descartado, trama de Seguridad MAC~~~~~\n");
			break;
			default:
				fprintf(arch,"~~~~~Paquete descartado, trama de IEEE 802.3~~~~~\n");
			break;
		}
		
	}else{
		
		fprintf(arch,"\n~~~~~Paquete Analizado Numero %d~~~~~\n",tot_paq-contador+1);
		
		ip_src.sin_addr.s_addr= ip_head->saddr;
		ip_dest.sin_addr.s_addr= ip_head->daddr;
		
		fprintf(arch,"\t- IP Fuente: %s\n",inet_ntoa(ip_src.sin_addr));
		fprintf(arch,"\t- IP Destino: %s\n",inet_ntoa(ip_dest.sin_addr));
		fprintf(arch,"\t- Longitud de Cabecera: %d \n",(unsigned int)ip_head->ihl*4);
		fprintf(arch,"\t- Longitud Total: %d \n",ntohs(ip_head->tot_len));
		fprintf(arch,"\t- Identificador: %d\n",ntohs(ip_head->id));
		fprintf(arch,"\t- Tiempo de Vida (TTL): %d\n",(unsigned int)ip_head->ttl);
		
		switch((unsigned int)ip_head->protocol){
			case 0X01:
				fprintf(arch,"\t- Protocolo de capa superior: ICMPv4\n");
				pxproto[0]++;
			break;
			case 0X02:
				fprintf(arch,"\t- Protocolo de capa superior: IGMP\n");
				pxproto[1]++;
			break;
			case 0X04:
				fprintf(arch,"\t- Protocolo de capa superior: IP\n");
				pxproto[2]++;
			break;
			case 0X06:
				fprintf(arch,"\t- Protocolo de capa superior: TCP\n");
				pxproto[3]++;
			break;
			case 0X11:
				fprintf(arch,"\t- Protocolo de capa superior: UDP\n");
				pxproto[4]++;
			break;
			case 0X29:
				fprintf(arch,"\t- Protocolo de capa superior: IPv6\n");
				pxproto[5]++;
			break;
			case 0X59:
				fprintf(arch,"\t- Protocolo de capa superior: OSPF\n");
				pxproto[6]++;
			break;
		}
		
		fprintf(arch,"\t- Carga Util (longitud): %d bytes\n",ntohs(ip_head->tot_len)-((unsigned int)ip_head->ihl*4));
		fprintf(arch,"\t- Tipo de Servicio:\n");
		
		switch(ip_head->tos & 0XE0){
			case 0X00:
				fprintf(arch,"\t|\t Precedencia: De Rutina\n");
			break;
			case 0X20:
				fprintf(arch,"\t|\t Precedencia: Prioritario\n");
			break;
			case 0X40:
				fprintf(arch,"\t|\t Precedencia: Inmediato\n");
			break;
			case 0X60:
				fprintf(arch,"\t|\t Precedencia: Relampago (flash)\n");
			break;
			case 0X80:
				fprintf(arch,"\t|\t Precedencia: Invalidacion Relampago\n");
			break;
			case 0XA0:
				fprintf(arch,"\t|\t Precedencia: Critico\n");
			break;
			case 0XC0:
				fprintf(arch,"\t|\t Precedencia: Control de Interred\n");
			break;
			case 0XD0:
				fprintf(arch,"\t|\t Precedencia: Control de Red\n");
			break;
		}
		
		switch(ip_head->tos & 0X1D){
			case 0X10:
				fprintf(arch,"\t|\t ToS: Minimiza Retardo\n");
			break;
			case 0X08:
				fprintf(arch,"\t|\t ToS: Maximiza Rendimiento\n");
			break;
			case 0X04:
				fprintf(arch,"\t|\t ToS: Maximiza Fiabilidad\n");
			break;
			case 0X02:
				fprintf(arch,"\t|\t ToS: Minimiza Coste Monetario\n");
			break;
			case 0X00:
				fprintf(arch,"\t|\t ToS: Servicio Normal\n");
			break;
		}
		
		printf("\nValor de desplazamiento: %x\n",(ip_head->frag_off & 0x1FFF));
		
		if((ip_head->frag_off & 0x4000)==0x4000){
			fprintf(arch,"\t- Fragmentación: No puede ser fragmentado\n");
			fprintf(arch,"\t- Ubicacion del Fragmento: Unico\n");
		}else{
			fprintf(arch,"\t- Fragmentación: Puede ser fragmentado\n");
			if((ip_head->frag_off & 0x2000)==0x2000){
				if((ip_head->frag_off & 0x1FFF)==0x0000){
					fprintf(arch,"\t- Numero Fragmento: Primero\n");
				}else{
					fprintf(arch,"\t- Numero Fragmento: Intermedio\n");
				}
			}else{
				if((ip_head->frag_off & 0x1FFF)==0x0000){
					fprintf(arch,"\t- Numero Fragmento: Unico\n");
				}else{
					fprintf(arch,"\t- Numero Fragmento: Ultimo\n");
				}
			}
		}

		fprintf(arch,"\t- Primer byte de datos: %d\n",ntohs(ip_head->frag_off & 0x1FFF)*8);
		fprintf(arch,"\t- Ultimo byte de datos: %d\n",(ntohs(ip_head->frag_off & 0x1FFF)*8)+(ntohs(ip_head->tot_len)-((unsigned int)ip_head->ihl*4)));
		
		if(ntohs(ip_head->tot_len)>0 && ntohs(ip_head->tot_len)<=159){
			pxlont[0]+=1;
		}else if(ntohs(ip_head->tot_len)>159 && ntohs(ip_head->tot_len)<=639){
			pxlont[1]+=1;
		}else if(ntohs(ip_head->tot_len)>639 && ntohs(ip_head->tot_len)<=1279){
			pxlont[2]+=1;
		}else if(ntohs(ip_head->tot_len)>1279 && ntohs(ip_head->tot_len)<=5119){
			pxlont[3]+=1;
		}else if(ntohs(ip_head->tot_len)>5119){
			pxlont[4]+=1;
		}
		
		contador-=1;

	}
	
	fprintf(arch,"\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
	
	fclose(arch);
	pthread_exit("Hilo Terminado\n");
}

void general_Report(){

	FILE *arch;
	arch=fopen("Reporte_Tramas.txt","a+");
	
	if(arch==NULL){
		arch=fopen("Reporte_Tramas.txt","w");
		fclose(arch);
		arch=fopen("Reporte_Tramas.txt","a+");
	}
	
	fprintf(arch,"~~Analisis completado~~\n\n");
	fprintf(arch,"Paquetes por Protocolo de Capa Superior.\n");
	fprintf(arch,"\t- Paquetes ICMPv4: %i\n",pxproto[0]);
	fprintf(arch,"\t- Paquetes IGMP:   %i\n",pxproto[1]);
	fprintf(arch,"\t- Paquetes IP:     %i\n",pxproto[2]);
	fprintf(arch,"\t- Paquetes TCP:    %i\n",pxproto[3]);
	fprintf(arch,"\t- Paquetes UDP:    %i\n",pxproto[4]);
	fprintf(arch,"\t- Paquetes IPv6:   %i\n",pxproto[5]);
	fprintf(arch,"\t- Paquetes OSPF:   %i\n\n",pxproto[6]);
	fprintf(arch,"Paquetes por Tamaño.\n");
	fprintf(arch,"\t- 0-159      bytes: %i\n",pxlont[0]);
	fprintf(arch,"\t- 160-639    bytes: %i\n",pxlont[1]);
	fprintf(arch,"\t- 640-1279   bytes: %i\n",pxlont[2]);
	fprintf(arch,"\t- 1280-5119  bytes: %i\n",pxlont[3]);
	fprintf(arch,"\t- 5120 o mas bytes: %i\n\n",pxlont[4]);
	
	fclose(arch);

}

