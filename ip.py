from audioop import reverse
from cgi import test
from doctest import debug_script
import struct
from grader.tcputils import calc_checksum, str2addr
from iputils import *


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.table = {}
        self.proximity = -1
        self.id = 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            self.proximity = -1
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            # Aqui pegamos todos os valores do datagrama, por precaução, porém quemos checksum em 0 para recalcular
            # e indice como nosso id lindo
            veihl, dscpecn, length, _ , flafrag, _, protocol, head_checksum , my, hop = struct.unpack('!BBHHHBBHII', datagrama[:20]) 
            var = [veihl, dscpecn, length, self.id, flafrag, ttl, protocol, 0, my, hop]
            
            # Função que calcula o datagrama
            if ttl > 1:
                datagrama = self.napolitano(payload, None, var)
            
            # Essa função retorna 'nop' caso não seja possível retransmitir
            else:   
                protocol = 1
                self.proximity = -1
                next_hop = self._next_hop(src_addr)
                dest = next_hop
                # Pulo do gato, é que a pessoa para onde iremos enviar é o própio src, caso a tabela nos retorne um ip com 0 valores iguais
                if 0 == self.proximity:
                    dest = src_addr
                # my define o destinatario 
                my, = struct.unpack('!I', str2addr(self.meu_endereco))
                # hop define o receptor
                hop, = struct.unpack('!I', str2addr(dest))

                # 64 pois, vamos resetar o ttl para iniciar a volta do sinal
                var = [veihl,dscpecn,length,self.id,flafrag,64,protocol,0,my,hop]
                # ip_header = struct.pack('!BBHHHBBHII', veihl, dscpecn, length, self.id, flafrag, ttl, protocol, head_checksum, my, hop)

                # Header icmp time exceed

                # Tipo do cabeçalho
                typ = 0x0b

                # Campo code do icmp
                code = 0

                # Inicialmente checksum 0
                checksum = 0

                # Foi pedido unused como 0
                unused = 0

                # Calculamos o bit até onde vai o corpo do icmp pelo tamanho do cabeçalho de ip + 8 bytes
                ihl = veihl & 0xf
                tam = 4*(ihl)+8
                
                # Calculando checksum para o icmp
                icmp_header = struct.pack('!BBHI', typ, code, checksum, unused) + (datagrama[:tam])
                
                checksum = calc_checksum(icmp_header)

                icmp_header = struct.pack('!BBHI', typ, code, checksum, unused) + (datagrama[:tam])
                
                # IMPORTANTE, o tamanho do datagrama muda, devido ao tamanho do payload ser o tamanho do cabeçalho icmp
                var[2] = 20 + len(icmp_header)

                # struct.pack do datagrama, montar datagrama
                datagrama = self.napolitano(icmp_header,None,var)

                self.enlace.enviar(datagrama, next_hop)
                return

            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        
        int_dest, = struct.unpack('!I', str2addr(dest_addr))
        # print(f'em int meu destino é = {int_dest}, e temos as opções {self.table}, nosso destino de verdade é {dest_addr}')
        for x in self.table.keys():
            # Converter o valor do cidr, desconsiderando os bits, usando a função do professor
            cidr,bits_desconsiderar = x.split('/')
            aux = int(bits_desconsiderar)
            bits_desconsiderar = 32 - aux
            cidr, = struct.unpack('!I', str2addr(cidr))
            # 32 é o máximo de bits que temos, poiss 4 campos com 8
            # >> shifta para a direita para tirar os bits que é pra desconsiderar, e << volta, para manter o tamanho
            cidr = cidr >> bits_desconsiderar << bits_desconsiderar
            # Faremos o mesmo para o valor a testar como chave
            teste_dest = int_dest >> bits_desconsiderar << bits_desconsiderar

            if(teste_dest == cidr):
                self.proximity = aux
                return self.table[x]

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        
        # Vamos focar em deixar o caso base ou seja /0 como último, pois queremos verifica-lo por último
        # na busca
        if len(self.table) > 0: 
            self.table.clear()

        # Nossa tabela será ordenada pela quantidade de bits considerados, sempre veremos assim o cidr
        # mais próximo do endereço recebido (em termos numéricos, não de distância)
        tabela.sort(key = lambda bits:int(bits[0].split('/')[1]), reverse = True)
       
        for endereco in tabela:
            self.table[endereco[0]] = endereco[1]

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        self.proximity = -1
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        
        # Função para montar o datagrama
        datagrama = self.napolitano(segmento, dest_addr, [])

        self.enlace.enviar(datagrama, next_hop)

       
    # Função para montar header e datagrama
    def napolitano(self, segmento, dest_addr, var):
        if 0 == len(var):
            # version e ihl     
            veihl = 0x45
            
            # kk desculpa (dscp) e ecn      
            dscpecn = 0x00

            #
            length = 20 + len(segmento)
            
            # Flags e fragment_offset
            flafrag = 0x00 
            
            # Time to live, quantos roteadores pode passar antes de desistir
            ttl = 64
            # Número do protocolo como tamo simulando tcp é 6
            protocol = 6
            header_checksum = 0
            address = self.id
            
            my = str2addr(self.meu_endereco)
            my, = struct.unpack('!I', my)
            hop = str2addr(dest_addr)
            hop, = struct.unpack('!I', hop)
            
            # aumenta o indice
            self.id += length
        else:
            veihl, dscpecn, length, address, flafrag, ttl, protocol, header_checksum, my, hop = var
            ttl -= 1
        # Primeiro calcula com checksum = 0
        ip_header = struct.pack('!BBHHHBBHII', veihl, dscpecn, length, address, flafrag, ttl, protocol, header_checksum, my, hop)
        
        # Ve o valor de checksum
        header_checksum = calc_checksum(ip_header)

        
        # Monta o cabeçalho com o valor alteradp
        ip_header = struct.pack('!BBHHHBBHII', veihl, dscpecn, length, address, flafrag, ttl, protocol, header_checksum, my, hop) 
        # Coloca o segmento depois do cabeçalho, pra mandar pra camada de enlace
        datagrama = ip_header + segmento

        
        return datagrama
