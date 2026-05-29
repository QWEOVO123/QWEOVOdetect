package org.detector.qweovodetect.stats;

import org.detector.qweovodetect.stats.model.RiskTarget;
import org.detector.qweovodetect.stats.model.SniLog;
import org.detector.qweovodetect.stats.model.SsLog;
import org.detector.qweovodetect.stats.model.TrojanLog;
import org.detector.qweovodetect.stats.repository.RiskTargetRepository;
import org.detector.qweovodetect.stats.repository.SniLogRepository;
import org.detector.qweovodetect.stats.repository.SsLogRepository;
import org.detector.qweovodetect.stats.repository.TrojanLogRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

@Service
public class StatsService {

    private final SniLogRepository sniLogRepository;
    private final SsLogRepository ssLogRepository;
    private final TrojanLogRepository trojanLogRepository;
    private final RiskTargetRepository riskTargetRepository;
    private final AuthConfigService authConfigService;

    public StatsService(SniLogRepository sniLogRepository,
                        SsLogRepository ssLogRepository,
                        TrojanLogRepository trojanLogRepository,
                        RiskTargetRepository riskTargetRepository,
                        AuthConfigService authConfigService) {
        this.sniLogRepository = sniLogRepository;
        this.ssLogRepository = ssLogRepository;
        this.trojanLogRepository = trojanLogRepository;
        this.riskTargetRepository = riskTargetRepository;
        this.authConfigService = authConfigService;
    }

    public void saveSni(String clientIp, String sniHost) {
        saveSni(clientIp, 0, sniHost);
    }

    public void saveSni(String clientIp, int listenPort, String sniHost) {
        saveSni(clientIp, listenPort, sniHost, "TLS");
    }

    public void saveSni(String clientIp, int listenPort, String sniHost, String protocol) {
        sniLogRepository.save(new SniLog(clientIp, listenPort, sniHost, protocol));
    }

    public List<Map<String, Object>> getTopSites() {
        return sniLogRepository.findTopSites().stream()
                .limit(30)
                .map(row -> mapOf("domain", row[0], "protocol", row[1], "count", row[2]))
                .toList();
    }

    public List<Map<String, Object>> getTopSitesLastHours(int hours) {
        return sniLogRepository.findTopSitesSince(LocalDateTime.now().minusHours(hours)).stream()
                .limit(30)
                .map(row -> mapOf("domain", row[0], "protocol", row[1], "count", row[2]))
                .toList();
    }

    public List<SniLog> getClientHistory(String ip) {
        return sniLogRepository.findByClientIpOrderByDetectTimeDesc(ip);
    }

    public List<Map<String, Object>> getAllClientsSummary() {
        return sniLogRepository.findDistinctPortClientPairs().stream().map(row -> {
            int listenPort = ((Number) row[0]).intValue();
            String ip = (String) row[1];
            List<Object[]> topDomains = sniLogRepository.findTopDomainsByPortAndIp(listenPort, ip);
            Map<String, Object> client = new LinkedHashMap<>();
            client.put("listenPort", listenPort);
            client.put("ip", ip);
            client.put("totalRequests", topDomains.stream().mapToLong(domain -> ((Number) domain[2]).longValue()).sum());
            client.put("topDomains", topDomains.stream().limit(20).map(domain ->
                    mapOf("domain", domain[0], "protocol", domain[1], "count", domain[2])
            ).toList());
            return client;
        }).toList();
    }

    public long getTotalCount() {
        return sniLogRepository.count();
    }

    public void saveSs(String clientIp, String targetIp) {
        saveSs(clientIp, 0, targetIp);
    }

    public void saveSs(String clientIp, int listenPort, String targetIp) {
        ssLogRepository.save(new SsLog(clientIp, listenPort, targetIp));
    }

    @Transactional
    public void saveTrojan(String clientIp, String targetIp, int uploadBytes, int downloadBytes) {
        saveTrojan(clientIp, 0, targetIp, uploadBytes, downloadBytes);
    }

    @Transactional
    public void saveTrojan(String clientIp, int listenPort, String targetIp, int uploadBytes, int downloadBytes) {
        trojanLogRepository.save(new TrojanLog(clientIp, listenPort, targetIp, uploadBytes, downloadBytes));
        incrementRiskTarget("TROJAN", listenPort, targetIp, "HIGH");
    }

    private void incrementRiskTarget(String protocol, int listenPort, String targetIp, String riskLevel) {
        RiskTarget target = riskTargetRepository.findByProtocolAndListenPortAndTargetIp(protocol, listenPort, targetIp)
                .orElseGet(() -> new RiskTarget(protocol, listenPort, targetIp, 0, riskLevel));
        target.setTriggerCount(target.getTriggerCount() + 1);
        target.setRiskLevel(riskLevel);
        target.setLastSeenTime(LocalDateTime.now());
        riskTargetRepository.save(target);
    }

    public List<Map<String, Object>> getSsClientRanking() {
        return ssLogRepository.findTopClientIps().stream().map(row ->
                mapOf("listenPort", row[0], "ip", row[1], "count", row[2])
        ).toList();
    }

    public List<Map<String, Object>> getHighRiskTargets() {
        List<Map<String, Object>> riskTargets = new ArrayList<>();

        riskTargets.addAll(ssLogRepository.findTopTargetIps().stream()
                .filter(row -> ((Number) row[2]).longValue() >= 30)
                .map(row -> {
                    int listenPort = ((Number) row[0]).intValue();
                    String targetIp = (String) row[1];
                    Map<String, Object> map = new LinkedHashMap<>();
                    map.put("listenPort", listenPort);
                    map.put("protocol", "SS");
                    map.put("ip", targetIp);
                    map.put("count", row[2]);
                    map.put("clients", mapClients(ssLogRepository.findClientsByPortAndTargetIp(listenPort, targetIp)));
                    return map;
                }).toList());

        riskTargets.addAll(riskTargetRepository.findByProtocolOrderByLastSeenTimeDesc("TROJAN").stream()
                .map(target -> {
                    Map<String, Object> map = new LinkedHashMap<>();
                    map.put("listenPort", target.getListenPort());
                    map.put("protocol", target.getProtocol());
                    map.put("ip", target.getTargetIp());
                    map.put("count", target.getTriggerCount());
                    map.put("riskLevel", target.getRiskLevel());
                    map.put("lastSeenTime", target.getLastSeenTime());
                    map.put("clients", mapClients(trojanLogRepository.findClientsByPortAndTargetIp(
                            target.getListenPort(), target.getTargetIp())));
                    return map;
                }).toList());

        return riskTargets.stream()
                .sorted(Comparator
                        .comparingInt((Map<String, Object> row) -> ((Number) row.get("listenPort")).intValue())
                        .thenComparing(row -> -((Number) row.get("count")).longValue()))
                .toList();
    }

    public long getSsTotal() {
        return ssLogRepository.count();
    }

    public long getTrojanTotal() {
        return trojanLogRepository.count();
    }

    public List<Map<String, Object>> getPortSummary() {
        Map<Integer, Map<String, Object>> ports = new TreeMap<>();
        for (AuthConfigService.InboundConfig inbound : authConfigService.currentInbounds()) {
            int port = inbound.port();
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("listenPort", port);
            item.put("nickname", inbound.nickname());
            item.put("enabled", inbound.enabled());
            item.put("authEnabled", inbound.authEnabled());
            item.put("clientCount", 0L);
            item.put("sniTotal", 0L);
            item.put("domainCount", 0L);
            item.put("ssTotal", 0L);
            item.put("trojanTotal", 0L);
            item.put("riskCount", 0L);
            item.put("topDomains", List.of());
            ports.put(port, item);
        }

        for (Object[] row : sniLogRepository.findPortSniSummary()) {
            int port = ((Number) row[0]).intValue();
            Map<String, Object> item = ports.computeIfAbsent(port, ignored -> new LinkedHashMap<>());
            item.put("listenPort", port);
            item.put("sniTotal", row[1]);
            item.put("clientCount", row[2]);
            item.put("domainCount", row[3]);
        }

        for (Object[] row : ssLogRepository.countByListenPort()) {
            ports.computeIfAbsent(((Number) row[0]).intValue(), ignored -> new LinkedHashMap<>())
                    .put("ssTotal", row[1]);
        }

        for (Object[] row : trojanLogRepository.countByListenPort()) {
            ports.computeIfAbsent(((Number) row[0]).intValue(), ignored -> new LinkedHashMap<>())
                    .put("trojanTotal", row[1]);
        }

        Map<Integer, Long> riskCounts = new TreeMap<>();
        for (Map<String, Object> risk : getHighRiskTargets()) {
            int port = ((Number) risk.get("listenPort")).intValue();
            riskCounts.merge(port, 1L, Long::sum);
        }
        riskCounts.forEach((port, count) -> ports.computeIfAbsent(port, ignored -> new LinkedHashMap<>())
                .put("riskCount", count));

        Map<Integer, List<Map<String, Object>>> domainsByPort = new TreeMap<>();
        for (Object[] row : sniLogRepository.findTopSitesByPortSince(LocalDateTime.now().minusHours(24))) {
            int port = ((Number) row[0]).intValue();
            domainsByPort.computeIfAbsent(port, ignored -> new ArrayList<>());
            if (domainsByPort.get(port).size() < 5) {
                domainsByPort.get(port).add(mapOf("domain", row[1], "protocol", row[2], "count", row[3]));
            }
        }
        domainsByPort.forEach((port, domains) -> ports.computeIfAbsent(port, ignored -> new LinkedHashMap<>())
                .put("topDomains", domains));

        return ports.values().stream().toList();
    }

    private List<Map<String, Object>> mapClients(List<Object[]> clients) {
        return clients.stream().map(row -> mapOf("ip", row[0], "count", row[1])).toList();
    }

    private Map<String, Object> mapOf(Object... pairs) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            map.put((String) pairs[i], pairs[i + 1]);
        }
        return map;
    }
}
