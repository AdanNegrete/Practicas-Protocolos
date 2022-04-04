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

int nicmpv4=0;
int nigmp=0;
int nip=0;
int ntcp=0;
int nudp=0;
int nipv6=0;
int nospf=0;
int plen[5]={0,0,0,0,0};

int contador;

typedef struct Datagrama{
	int numero;
	int longitud;
	unsigned char buffer[65536];
}Paquete;

void reporte(){

	FILE *arch;
	arch=fopen("ReportePaquetes.txt","a+");
	
	if(arch==NULL){
		arch=fopen("ReportePaquetes.txt","w");
		fclose(arch);
		arch=fopen("ReportePaquetes.txt","a+");
	}
	
	fprintf(arch,"********Reporte Paquetes********\nPor Protocolo de Capa Superior.\n\t| ICMPv4: %i\n\t| IGMP: %i\n\t| IP: %i\n\t| TCP: %i\n\t| UDP: %i\n\t| IPv6: %i\n\t| OSPF: %i\n\nPor Tamaño.\n\t| 0 a 159: %i\n\t| 160 a 639: %i\n\t| 640 a 1279: %i\n\t| 1280 a 5119: %i\n\t| 5120 o mas: %i\n\n",nicmpv4, nigmp, nip, ntcp, nudp, nipv6, nospf, plen[0], plen[1], plen[2], plen[3], plen[4]);

}

void *analizar_Paquete(void *arg){
	
	unsigned char tram_tip[2];
	__be16 pro_tip;
	__u8 precedencia;
	__u8 ToS;
	
	FILE *arch;
	
	Paquete *tram=(Paquete *)arg;
	
	struct sockaddr_in source,dest;
	struct ethhdr *ether;
	struct iphdr *ipdata;
	
	ether=(struct ethhdr*)tram->buffer;
	ipdata=(struct iphdr*)(tram->buffer + sizeof(struct ethhdr));
	
	memset(&tram_tip,0, sizeof(tram_tip));
	
	arch=fopen("PaquetesAnalizados.txt","a+");
	
	if(arch==NULL){
		arch=fopen("PaquetesAnalizados.txt","w");
		fclose(arch);
		arch=fopen("PaquetesAnalizados.txt","a+");
	}
	
	tram_tip[0]=ether->h_proto>>8;
	tram_tip[1]=ether->h_proto;
	pro_tip=tram_tip[1]<<8;
	pro_tip=pro_tip^tram_tip[0];
	
	if(pro_tip!=0X0800){
		
		printf("\nPaquete Descartado\n\n");
		
	}else{
		
		source.sin_addr.s_addr= ipdata->saddr;
		dest.sin_addr.s_addr= ipdata->daddr;
		
		fprintf(arch,"----Paquete %d----\n",tram->numero);
		fprintf(arch,"IP Fuente: %s\n",inet_ntoa(source.sin_addr));
		fprintf(arch,"IP Destino: %s\n",inet_ntoa(dest.sin_addr));
		fprintf(arch,"Longitud de la cabecera: %d \n",(unsigned int)ipdata->ihl*4);
		fprintf(arch,"Longitud total: %d \n",ntohs(ipdata->tot_len));
		fprintf(arch,"Identificador: %d\n",ntohs(ipdata->id));
		fprintf(arch,"TTL: %d\n",(unsigned int)ipdata->ttl);
		
		switch((unsigned int)ipdata->protocol){
			case 0X01:
				fprintf(arch,"Protocolo de capa superior: ICMPv4\n");
				nicmpv4++;
			break;
			case 0X02:
				fprintf(arch,"Protocolo de capa superior: IGMP\n");
				nigmp++;
			break;
			case 0X04:
				fprintf(arch,"Protocolo de capa superior: IP\n");
				nip++;
			break;
			case 0X06:
				fprintf(arch,"Protocolo de capa superior: TCP\n");
				ntcp++;
			break;
			case 0X11:
				fprintf(arch,"Protocolo de capa superior: UDP\n");
				nudp++;
			break;
			case 0X29:
				fprintf(arch,"Protocolo de capa superior: IPv6\n");
				nipv6++;
			break;
			case 0X59:
				fprintf(arch,"Protocolo de capa superior: OSPF\n");
				nospf++;
			break;
		}
		fprintf(arch,"Longitud de carga util: %d\n",ntohs(ipdata->tot_len)-((unsigned int)ipdata->ihl*4));
		fprintf(arch,"Tipo de Servicio:\n");
		
		precedencia=ipdata->tos & 0XE0;
		
		switch(precedencia){
			case 0X00:
				fprintf(arch,"\tPrecedencia: De Rutina\n");
			break;
			case 0X20:
				fprintf(arch,"\tPrecedencia: Prioritario\n");
			break;
			case 0X40:
				fprintf(arch,"\tPrecedencia: Inmediato\n");
			break;
			case 0X60:
				fprintf(arch,"\tPrecedencia: Relampago (flash)\n");
			break;
			case 0X80:
				fprintf(arch,"\tPrecedencia: Invalidacion Relampago\n");
			break;
			case 0XA0:
				fprintf(arch,"\tPrecedencia: Critico\n");
			break;
			case 0XC0:
				fprintf(arch,"\tPrecedencia: Control de Interred\n");
			break;
			case 0XD0:
				fprintf(arch,"\tPrecedencia: Control de Red\n");
			break;
		}
		
		ToS=ipdata->tos & 0X1D;
		
		switch(ToS){
			case 0X10:
				fprintf(arch,"\tToS: Minimiza Retardo\n");
			break;
			case 0X08:
				fprintf(arch,"\tToS: Maximiza Rendimiento\n");
			break;
			case 0X04:
				fprintf(arch,"\tToS: Maximiza Fiabilidad\n");
			break;
			case 0X02:
				fprintf(arch,"\tToS: Minimiza Coste $\n");
			break;
			case 0X00:
				fprintf(arch,"\tToS: Servicio Normal\n");
			break;
		}
		
		if((ipdata->frag_off & 0x4000)==0x4000){
			fprintf(arch,"Se puede fragmentar: No\n");
			fprintf(arch,"Numero de fragmento: Unico\n");
		}else{
			fprintf(arch,"Se puede fragmentar: Si\n");
			if((ipdata->frag_off & 0x2000)==0x2000){
				if((ipdata->frag_off & 0x1FFF)==0x0000){
					fprintf(arch,"Numero de fragmento: Primero\n");
				}else{
					fprintf(arch,"Numero de fragmento: Intermedio\n");
				}
			}else{
				if((ipdata->frag_off & 0x1FFF)==0x0000){
					fprintf(arch,"Numero de fragmento: Unico\n");
				}else{
					fprintf(arch,"Numero de fragmento: Ultimo\n");
				}
			}
		}

		fprintf(arch,"Primer byte del datagrama: %d\n",ntohs(ipdata->frag_off & 0x1FFF)*8);
		fprintf(arch,"Ultimo byte del datagrama: %d\n",(ntohs(ipdata->frag_off & 0x1FFF)*8)+(ntohs(ipdata->tot_len)-((unsigned int)ipdata->ihl*4)));
		
		contador-=1;

	}
	
	fprintf(arch,"\n***********************************************\n");
	
	if(ntohs(ipdata->tot_len)>0 && ntohs(ipdata->tot_len)<=159){
		plen[0]+=1;
	}else if(ntohs(ipdata->tot_len)>159 && ntohs(ipdata->tot_len)<=639){
		plen[1]+=1;
	}else if(ntohs(ipdata->tot_len)>639 && ntohs(ipdata->tot_len)<=1279){
		plen[2]+=1;
	}else if(ntohs(ipdata->tot_len)>1279 && ntohs(ipdata->tot_len)<=5119){
		plen[3]+=1;
	}else if(ntohs(ipdata->tot_len)>5119){
		plen[4]+=1;
	}
	
	fclose(arch);
	pthread_exit("Hilo Terminado\n");
}

int main(int argc, char *argv[]){
	
	char *adpt;
	char *npaquetes;
	int len_addr;
	int sockfd;  
	
	if (argc < 2) {
		printf ("usage: %s adaptador %s npaquetes\n", argv[0],argv[1]);
		exit (1);
	}
	
	adpt = argv[1];
	npaquetes = argv[2];
	contador=atoi(npaquetes);
	
	Paquete pack;
	pthread_t hilo_anz;
	struct sockaddr saddr;
	
	len_addr=sizeof(saddr);
	
	
	sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(sockfd == -1){	
		fprintf(stderr, "Falla en la creacion de socket. %d: %s \n",errno, strerror(errno));
		return -1;
	}else{
		printf("Socket creado con exito\n");
	}
	
	struct ifreq iphreq;
	strncpy(iphreq.ifr_name,adpt,IFNAMSIZ);
	ioctl(sockfd,SIOCGIFFLAGS,&iphreq);
	iphreq.ifr_flags |= IFF_PROMISC;
	if(ioctl(sockfd,SIOCSIFFLAGS,&iphreq)<0){
		printf("\nNo se pudo configurar el modo promiscuo\n");
		return -1;
	}else{
		printf("\nModo promiscuo activado\n");
	}
	
	printf("\nIniciando Recoleccion de npaquetes...\n");
	
	while(contador>0){
		
		memset(&pack,0, sizeof(pack));
		memset(&saddr,0, sizeof(saddr));
		
		pack.longitud=recvfrom(sockfd, pack.buffer, 65536, 0,&saddr, (socklen_t*)&len_addr);
		
		if(pack.longitud == 0)
			printf("\n[Error]: No se recibió mensaje \n");
		
		if(pack.longitud < 0){
			fprintf(stderr, "[Error]: Mensaje no leído. %d: %s \n",errno, strerror(errno));
		}else{
			pack.numero=atoi(npaquetes)-contador+1;
	
			if(pthread_create(&hilo_anz,NULL,analizar_Paquete,(void *)&pack)){
				printf("[Error]: No pudo crearse el hilo\n");
				exit(EXIT_FAILURE);
			}
			
			if(pthread_join(hilo_anz,NULL)){
				printf("[Error]: No pse pudo conectar al hilo\n");
				exit(EXIT_FAILURE);
			}else{
				printf("Paquete %i analizado!!!\n",pack.numero);
			}
			
		}
			
	}
	
	reporte();
	
	char instruccion[100]="";
	
	strcat(instruccion,"/sbin/ifconfig ");
	strcat(instruccion,adpt);
	strcat(instruccion," -promisc");
	
	system(instruccion);
	
}

