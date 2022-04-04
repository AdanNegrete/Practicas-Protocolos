//Librerias
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>

#define BUFFER_LEN 	65536

int pppro[7]={0,0,0,0,0,0,0};
int pplen[5]={0,0,0,0,0};

int cont;

void *analizador(void *arg){
	
	unsigned char tram_tip[2];
	__be16 pro_tip;
	char proto[50];
	__u8 precedencia;
	__u8 ToS;
	unsigned char *buffer=(unsigned char *)arg;
	
	FILE *archivo;
	
	struct sockaddr_in source,dest;
	struct ethhdr *ether;
	struct iphdr *ip_pack;
	
	ether=(struct ethhdr*)buffer;
	ip_pack=(struct iphdr*)(buffer + sizeof(struct ethhdr));
	
	memset(&proto,0, sizeof(proto));
	memset(&tram_tip,0, sizeof(tram_tip));
	
	archivo=fopen("Paquetes.txt","a+");
	
	if(archivo==NULL){
		archivo=fopen("Paquetes.txt","w");
		fclose(archivo);
		archivo=fopen("Paquetes.txt","a+");
	}
	
	tram_tip[0]=ether->h_proto>>8;
	tram_tip[1]=ether->h_proto;
	pro_tip=tram_tip[1]<<8;
	pro_tip=pro_tip^tram_tip[0];
	
	if(pro_tip!=0X0800){
		
		fprintf(archivo,"\n***Trama no analizada, tipo diferente de IPV4***\n\n");
		
	}else{
		
		source.sin_addr.s_addr= ip_pack->saddr;
		dest.sin_addr.s_addr= ip_pack->daddr;
		
		fprintf(archivo,"\nDireccion IP Fuente: \t%s\n",inet_ntoa(source.sin_addr));
		fprintf(archivo,"\nDireccion IP Destino: \t%s\n",inet_ntoa(dest.sin_addr));
		fprintf(archivo,"\nLongitud Cabecera: \t%d \n",(unsigned int)ip_pack->ihl*4);
		fprintf(archivo,"\nLongitud Total Trama: \t%d \n",ntohs(ip_pack->tot_len));
		fprintf(archivo,"\nIdentificador Datagrama: %d\n",ntohs(ip_pack->id));
		fprintf(archivo,"\nTiempo de Vida (TTL): %d\n",(unsigned int)ip_pack->ttl);
		
		switch((unsigned int)ip_pack->protocol){
			case 0X01:
				strcpy(proto,"ICMPv4");
				pppro[0]++;
			break;
			case 0X02:
				strcpy(proto,"IGMP");
				pppro[1]++;
			break;
			case 0X04:
				strcpy(proto,"IP");
				pppro[2]++;
			break;
			case 0X06:
				strcpy(proto,"TCP");
				pppro[3]++;
			break;
			case 0X11:
				strcpy(proto,"UDP");
				pppro[4]++;
			break;
			case 0X29:
				strcpy(proto,"IPv6");
				pppro[5]++;
			break;
			case 0X59:
				strcpy(proto,"OSPF");
				pppro[6]++;
			break;
		}
		fprintf(archivo,"\nProtocolo Superior: \t%s\n",proto);
		fprintf(archivo,"\nLongitud Carga Util: \t%d\n",ntohs(ip_pack->tot_len)-((unsigned int)ip_pack->ihl*4));
		
		precedencia=ip_pack->tos & 0XE0;
		
		switch(precedencia){
			case 0X00:
				fprintf(archivo,"\nPrecedencia: \t    De Rutina\n");
			break;
			case 0X20:
				fprintf(archivo,"\nPrecedencia: \t    Prioritario\n");
			break;
			case 0X40:
				fprintf(archivo,"\nPrecedencia: \t    Inmediato\n");
			break;
			case 0X60:
				fprintf(archivo,"\nPrecedencia: \t    Relampago (flash)\n");
			break;
			case 0X80:
				fprintf(archivo,"\nPrecedencia: \t    Invalidacion Relampago\n");
			break;
			case 0XA0:
				fprintf(archivo,"\nPrecedencia: \t    Critico\n");
			break;
			case 0XC0:
				fprintf(archivo,"\nPrecedencia: \t    Control de Interred\n");
			break;
			case 0XD0:
				fprintf(archivo,"\nPrecedencia: \t    Control de Red\n");
			break;
		}
		
		ToS=ip_pack->tos & 0X1D;
		
		switch(precedencia){
			case 0X10:
				fprintf(archivo,"\nTipo de Servicio: \tMinimiza Retardo\n");
			break;
			case 0X08:
				fprintf(archivo,"\nTipo de Servicio: \tMaximiza Rendimiento\n");
			break;
			case 0X04:
				fprintf(archivo,"\nTipo de Servicio: \tMaximiza Fiabilidad\n");
			break;
			case 0X02:
				fprintf(archivo,"\nTipo de Servicio: \tMinimiza Coste $\n");
			break;
			case 0X00:
				fprintf(archivo,"\nTipo de Servicio: \tServicio Normal\n");
			break;
		}
		
		if((ip_pack->frag_off & 0x4000)==0x4000){
			fprintf(archivo,"\nFragmentación: \tNo se puede fragmentar\n");
			fprintf(archivo,"\nNumero Fragmento: \tUnico\n");
		}else{
			fprintf(archivo,"\nFragmentación: \tSe puede fragmentar\n");
			if((ip_pack->frag_off & 0x2000)==0x2000){
				if((ip_pack->frag_off & 0x1FFF)==0x0000){
					fprintf(archivo,"\nNumero Fragmento: \tPrimero\n");
				}else{
					fprintf(archivo,"\nNumero Fragmento: \tIntermedio\n");
				}
			}else{
				if((ip_pack->frag_off & 0x1FFF)==0x0000){
					fprintf(archivo,"\nNumero Fragmento: \tUnico\n");
				}else{
					fprintf(archivo,"\nNumero Fragmento: \tUltimo\n");
				}
			}
		}

		fprintf(archivo,"\nPrimer byte: \t%d\n",ntohs(ip_pack->frag_off & 0x1FFF)*8);
		fprintf(archivo,"\nUltimo byte: \t%d\n",(ntohs(ip_pack->frag_off & 0x1FFF)*8)+(ntohs(ip_pack->tot_len)-((unsigned int)ip_pack->ihl*4)));
		
		cont-=1;
		
		if(ntohs(ip_pack->tot_len)>0 && ntohs(ip_pack->tot_len)<=159){
			pplen[0]+=1;
		}else if(ntohs(ip_pack->tot_len)>159 && ntohs(ip_pack->tot_len)<=639){
			pplen[1]+=1;
		}else if(ntohs(ip_pack->tot_len)>639 && ntohs(ip_pack->tot_len)<=1279){
			pplen[2]+=1;
		}else if(ntohs(ip_pack->tot_len)>1279 && ntohs(ip_pack->tot_len)<=5119){
			pplen[3]+=1;
		}else if(ntohs(ip_pack->tot_len)>5119){
			pplen[4]+=1;
		}

	}
	
	fprintf(archivo,"\n-------------------------------------------------\n");
	
	fclose(archivo);
	pthread_exit("Hilo Terminado\n");
}

void estadisticas(){

	FILE *archivo;
	archivo=fopen("Paquetes.txt","a+");
	
	fprintf(archivo,"\n-------------------------------------------------\n");
	fprintf(archivo,"\n\tEstadísticas de Paquetes\nPaquetes por Protocolo de Capa Superior.\n\tTramas ICMPv4: %i\n\tTramas IGMP: %i\n\tTramas IP: %i\n\tTramas TCP: %i\n\tTramas UDP: %i\n\tTramas IPv6: %i\n\tTramas OSPF: %i\n\nPaquetes por Tamaño.\n\t0-159: %i\n\t160-639: %i\n\t640-1279: %i\n\t1280-5119: %i\n\t5120 o mas: %i\n\n", pppro[0],pppro[1],pppro[2],pppro[3],pppro[4],pppro[5],pppro[6],pplen[0],pplen[1],pplen[2],pplen[3],pplen[4]);

}

int main(){
	
	char adaptador[10]="";
	char num_paq[10]="";
	int sockfd; 
	int len_addr;
	int len_pack;
	unsigned char packet[BUFFER_LEN]; 
	pthread_t hilo_analiza;
	struct sockaddr saddr;
	
	printf("\nCantidad de paquetes solicitada: ");
	gets(num_paq);
	printf("\nAdaptador de Red: ");
	gets(adaptador);
	
	cont=atoi(num_paq);
	
	len_addr=sizeof(saddr);
	
	sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(sockfd == -1){	
		fprintf(stderr, "Error abriendo el socket. %d: %s \n",errno, strerror(errno));
		return -1;
	}else{
		printf("Socket abierto\n");
	}
	
	struct ifreq iphreq;
	strncpy(iphreq.ifr_name,adaptador,IFNAMSIZ);
	ioctl(sockfd,SIOCGIFFLAGS,&iphreq);
	iphreq.ifr_flags |= IFF_PROMISC;
	if(ioctl(sockfd,SIOCSIFFLAGS,&iphreq)<0){
		printf("\nError configurando la red\n");
		return -1;
	}else{
		printf("\nRed configurada en modo promiscuo\n");
	}
	
	while(cont>0){
		
		memset(&packet,0, sizeof(packet));
		memset(&saddr,0, sizeof(saddr));
		
		len_pack=recvfrom(sockfd, packet, BUFFER_LEN, 0,&saddr, (socklen_t*)&len_addr);
		
		if(len_pack == 0)
			printf("\nNo hay paquete \n");
		
		if(len_pack < 0){
			fprintf(stderr, "Paquete no obtenido. %d: %s \n",errno, strerror(errno));
		}else{
	
			if(pthread_create(&hilo_analiza,NULL,analizador,(void *)&packet)){
				printf("Error de creación de hilo\n");
				exit(EXIT_FAILURE);
			}
			
			if(pthread_join(hilo_analiza,NULL)){
				printf("Error conectando con el hilo\n");
				exit(EXIT_FAILURE);
			}else{
				printf("Se analizó el paquete %i\n",cont+1);
			}
			
		}
			
	}
	
	estadisticas(atoi(num_paq));
	
	system("/sbin/ifconfig enp0s3 -promisc");
	
}

