package org.detector.qweovodetect.stats;

import org.detector.qweovodetect.stats.model.SniLog;
import org.detector.qweovodetect.stats.model.SsLog;
import org.detector.qweovodetect.stats.model.RiskTarget;
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

@Service
public class StatsService {

    private final SniLogRepository sniLogRepository;
    private final SsLogRepository ssLogRepository;
    private final TrojanLogRepository trojanLogRepository;
    private final RiskTargetRepository riskTargetRepository;

    public StatsService(SniLogRepository sniLogRepository,
                        SsLogRepository ssLogRepository,
                        TrojanLogRepository trojanLogRepository,
                        RiskTargetRepository riskTargetRepository) {
        this.sniLogRepository = sniLogRepository;
        this.ssLogRepository = ssLogRepository;
        this.trojanLogRepository = trojanLogRepository;
        this.riskTargetRepository = riskTargetRepository;
    }

    // ===== SNI =====

    public void saveSni(String clientIp, String sniHost) {
        sniLogRepository.save(new SniLog(clientIp, sniHost));
    }

    public List<Map<String, Object>> getTopSites() {
        return sniLogRepository.findTopSites().stream()
                .limit(30)
                .map(row -> {
                    Map<String, Object> map = new LinkedHashMap<>();
                    map.put("domain", row[0]);
                    map.put("count", row[1]);
                    return map;
                })
                .toList();
    }

    public List<Map<String, Object>> getTopSitesLastHours(int hours) {
        return sniLogRepository.findTopSitesSince(LocalDateTime.now().minusHours(hours)).stream()
                .limit(30)
                .map(row -> {
                    Map<String, Object> map = new LinkedHashMap<>();
                    map.put("domain", row[0]);
                    map.put("count", row[1]);
                    return map;
                })
                .toList();
    }

    public List<SniLog> getClientHistory(String ip) {
        return sniLogRepository.findByClientIpOrderByDetectTimeDesc(ip);
    }

    public List<Map<String, Object>> getAllClientsSummary() {
        List<String> clientIps = sniLogRepository.findDistinctClientIps();
        return clientIps.stream().map(ip -> {
            List<Object[]> topDomains = sniLogRepository.findTopDomainsByIp(ip);
            Map<String, Object> client = new LinkedHashMap<>();
            client.put("ip", ip);
            client.put("totalRequests", topDomains.stream().mapToLong(row -> (Long) row[1]).sum());
            client.put("topDomains", topDomains.stream().limit(20).map(row -> {
                Map<String, Object> domain = new LinkedHashMap<>();
                domain.put("domain", row[0]);
                domain.put("count", row[1]);
                return domain;
            }).toList());
            return client;
        }).toList();
    }

    public long getTotalCount() {
        return sniLogRepository.count();
    }

    // ===== SS =====

    public void saveSs(String clientIp, String targetIp) {
        ssLogRepository.save(new SsLog(clientIp, targetIp));
    }

    @Transactional
    public void saveTrojan(String clientIp, String targetIp, int uploadBytes, int downloadBytes) {
        trojanLogRepository.save(new TrojanLog(clientIp, targetIp, uploadBytes, downloadBytes));

        LocalDateTime since = LocalDateTime.now().minusMinutes(3);
        long recentCount = trojanLogRepository.countByTargetIpAndDetectTimeGreaterThanEqual(targetIp, since);
        markRiskTarget("TROJAN", targetIp, recentCount, "HIGH");
    }

    private void markRiskTarget(String protocol, String targetIp, long triggerCount, String riskLevel) {
        RiskTarget target = riskTargetRepository.findByProtocolAndTargetIp(protocol, targetIp)
                .orElseGet(() -> new RiskTarget(protocol, targetIp, triggerCount, riskLevel));
        target.setTriggerCount(Math.max(target.getTriggerCount(), triggerCount));
        target.setRiskLevel(riskLevel);
        target.setLastSeenTime(LocalDateTime.now());
        riskTargetRepository.save(target);
    }

    public List<Map<String, Object>> getSsClientRanking() {
        return ssLogRepository.findTopClientIps().stream().map(row -> {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("ip", row[0]);
            map.put("count", row[1]);
            return map;
        }).toList();
    }

    public List<Map<String, Object>> getHighRiskTargets() {
        List<Map<String, Object>> riskTargets = new ArrayList<>();

        riskTargets.addAll(ssLogRepository.findTopTargetIps().stream()
                .filter(row -> (Long) row[1] >= 30)
                .map(row -> {
                    Map<String, Object> map = new LinkedHashMap<>();
                    String targetIp = (String) row[0];
                    map.put("protocol", "SS");
                    map.put("ip", targetIp);
                    map.put("count", row[1]);
                    List<Object[]> clients = ssLogRepository.findClientsByTargetIp(targetIp);
                    map.put("clients", clients.stream().map(c -> {
                        Map<String, Object> cm = new LinkedHashMap<>();
                        cm.put("ip", c[0]);
                        cm.put("count", c[1]);
                        return cm;
                    }).toList());
                    return map;
                }).toList());

        riskTargets.addAll(riskTargetRepository.findByProtocolOrderByLastSeenTimeDesc("TROJAN").stream()
                .map(target -> {
                    Map<String, Object> map = new LinkedHashMap<>();
                    map.put("protocol", target.getProtocol());
                    map.put("ip", target.getTargetIp());
                    map.put("count", target.getTriggerCount());
                    map.put("riskLevel", target.getRiskLevel());
                    map.put("lastSeenTime", target.getLastSeenTime());
                    List<Object[]> clients = trojanLogRepository.findClientsByTargetIp(target.getTargetIp());
                    map.put("clients", clients.stream().map(c -> {
                        Map<String, Object> cm = new LinkedHashMap<>();
                        cm.put("ip", c[0]);
                        cm.put("count", c[1]);
                        return cm;
                    }).toList());
                    return map;
                }).toList());

        return riskTargets.stream()
                .sorted(Comparator.comparingLong(row -> -((Number) row.get("count")).longValue()))
                .toList();
    }

    public long getSsTotal() {
        return ssLogRepository.count();
    }

    public long getTrojanTotal() {
        return trojanLogRepository.count();
    }
}
