#!/usr/bin/python
#coding=utf-8


from PackageScanner.Functions.Subnet.HTTPServer.OutputFormatter import *
from PackageScanner.Functions.Subnet.HTTPServer.Job import HTTPHeaderJob
from PackageScanner.Scanner import Scanner_v1


class FindHTTPServer(Scanner_v1):
    def __init__(self, ports):
        Scanner_v1.__init__(self)
        self._ports = ports
        self._outputFormatters.append(OutputFormatterConsoleHTTPServer())
        self._outputFormatters.append(OutputFormatterFileHTTPServer())

    def createJobs(self,targets):
        for index1, port in enumerate(self._ports):
            for index2, ip in enumerate(targets):
                if targets.size > 1 and ip in [targets.network, targets.broadcast]:
                    continue
                self._jobQueue.addJob(HTTPHeaderJob(((index1) * len(targets))+(index2+1), str(ip), port))

        return len(self._ports) * len(targets)


if __name__ == '__main__':
    import socket
    socket.setdefaulttimeout(3)
    s = FindHTTPServer(ports=[80,81,82,83,8000,8001,8002,8003,8080,8088])
    import netaddr
    net = netaddr.IPNetwork('118.193.216.0/24')
    s._description = str(net.network)
    s.scan(targets=net, thread_count= 32)
    for r in s:
        pass