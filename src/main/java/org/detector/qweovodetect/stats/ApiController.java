package org.detector.qweovodetect.stats;

import org.detector.qweovodetect.stats.model.SniLog;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ApiController {

    private final StatsService statsService;

    public ApiController(StatsService statsService) {
        this.statsService = statsService;
    }

    // 域名排行
    @GetMapping("/top-sites")
    public List<Map<String, Object>> topSites(@RequestParam(defaultValue = "24") int hours) {
        return statsService.getTopSitesLastHours(hours);
    }
    // 所有客户端的访问排行
    @GetMapping("/all-clients")
    public List<Map<String, Object>> allClients() {
        return statsService.getAllClientsSummary();
    }

    // 总记录数
    @GetMapping("/total")
    public Map<String, Object> total() {
        return Map.of("total", statsService.getTotalCount());
    }

    // 某 IP 的历史
    @GetMapping("/client/{ip}")
    public List<SniLog> clientHistory(@PathVariable String ip) {
        return statsService.getClientHistory(ip);
    }
    // SS 客户端排行
    @GetMapping("/ss/client-ranking")
    public List<Map<String, Object>> ssClientRanking() {
        return statsService.getSsClientRanking();
    }

    // 高危目标 IP
    @GetMapping("/ss/high-risk")
    public List<Map<String, Object>> ssHighRisk() {
        return statsService.getHighRiskTargets();
    }

    // SS 总数
    @GetMapping("/ss/total")
    public Map<String, Object> ssTotal() {
        return Map.of("total", statsService.getSsTotal());
    }

    @GetMapping("/trojan/total")
    public Map<String, Object> trojanTotal() {
        return Map.of("total", statsService.getTrojanTotal());
    }
}
