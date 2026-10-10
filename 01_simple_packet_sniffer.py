#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
أداة اعتراض الحزم البسيطة (Packet Sniffer)
Safe Educational Tool - استخدم على شبكتك الخاصة فقط
"""

import scapy.all as scapy
import re
from collections import defaultdict

class SimplePacketSniffer:
    """أداة بسيطة وآمنة لاعتراض الحزم"""
    
    def __init__(self):
        self.packet_count = 0
        self.data_found = defaultdict(list)
    
    def analyze_packet(self, packet):
        """تحليل الحزمة"""
        self.packet_count += 1
        
        # طباعة معلومات الحزمة
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            
            print(f"\n{'='*50}")
            print(f"[الحزمة #{self.packet_count}]")
            print(f"من: {ip_src} → إلى: {ip_dst}")
            
            # فحص البيانات الخام
            if packet.haslayer(scapy.Raw):
                self.check_sensitive_data(packet[scapy.Raw].load)
            
            # معلومات TCP
            if packet.haslayer(scapy.TCP):
                print(f"بروتوكول: TCP")
                print(f"المنفذ المصدر: {packet[scapy.TCP].sport}")
                print(f"المنفذ الهدف: {packet[scapy.TCP].dport}")
            
            # معلومات UDP
            elif packet.haslayer(scapy.UDP):
                print(f"بروتوكول: UDP")
                print(f"المنفذ المصدر: {packet[scapy.UDP].sport}")
                print(f"المنفذ الهدف: {packet[scapy.UDP].dport}")
    
    def check_sensitive_data(self, data):
        """البحث عن بيانات حساسة"""
        try:
            decoded = data.decode('utf-8', errors='ignore')
            
            # البحث عن بريد إلكتروني
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', decoded)
            if emails:
                print(f"📧 بريد إلكتروني: {emails}")
                self.data_found['emails'].extend(emails)
            
            # البحث عن كلمات مرور
            if re.search(r'password\s*[:=]\s*[^\s&]+', decoded, re.IGNORECASE):
                print(f"🔓 ⚠️ كلمة مرور مكتشفة!")
                self.data_found['passwords'].append(decoded[:100])
            
            # البحث عن توكنات
            if re.search(r'token\s*[:=]\s*[^\s&]+', decoded, re.IGNORECASE):
                print(f"🔑 ⚠️ توكن مكتشف!")
                self.data_found['tokens'].append(decoded[:100])
            
            # البحث عن API Key
            if re.search(r'api[_-]?key\s*[:=]\s*[^\s&]+', decoded, re.IGNORECASE):
                print(f"🔐 ⚠️ API Key مكتشفة!")
                self.data_found['api_keys'].append(decoded[:100])
        
        except:
            pass
    
    def run(self, packet_count=0, interface=None):
        """تشغيل الأداة"""
        print("\n" + "="*50)
        print("🔍 أداة اعتراض الحزم (Packet Sniffer)")
        print("="*50)
        print("⚠️  استخدم هذه الأداة على شبكتك الخاصة فقط!")
        print("⚠️  اضغط Ctrl+C للإيقاف\n")
        
        try:
            if packet_count > 0:
                scapy.sniff(iface=interface, prn=self.analyze_packet, store=False, count=packet_count)
            else:
                scapy.sniff(iface=interface, prn=self.analyze_packet, store=False)
        
        except KeyboardInterrupt:
            self.print_report()
        except PermissionError:
            print("❌ خطأ: تحتاج صلاحيات ROOT/Administrator")
            print("جرب: sudo python3 script.py")
    
    def print_report(self):
        """طباعة التقرير"""
        print("\n" + "="*50)
        print(f"📊 التقرير النهائي")
        print("="*50)
        print(f"إجمالي الحزم: {self.packet_count}")
        
        if self.data_found:
            print("\n[البيانات المكتشفة]")
            for category, items in self.data_found.items():
                print(f"\n{category.replace('_', ' ').title()}:")
                for item in set(items):
                    print(f"  • {item}")
        else:
            print("✅ لم يتم اكتشاف بيانات حساسة")


# الاستخدام
if __name__ == "__main__":
    sniffer = SimplePacketSniffer()
    
    # اختر أحد الخيارات:
    
    # 1. اعتراض أول 50 حزمة
    sniffer.run(packet_count=50)
    
    # 2. اعتراض مستمر (اضغط Ctrl+C للإيقاف)
    # sniffer.run()
    
    # 3. اعتراض على واجهة محددة (إذا كانت لديك أكثر من واحدة)
    # sniffer.run(interface="eth0")
