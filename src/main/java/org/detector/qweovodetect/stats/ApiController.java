package org.detector.qweovodetect.stats;

import org.detector.qweovodetect.stats.model.SniLog;
import org.detector.qweovodetect.stats.model.BlockRule;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ApiController {

    private final StatsService statsService;
    private final BlockRuleService blockRuleService;

    public ApiController(StatsService statsService, BlockRuleService blockRuleService) {
        this.statsService = statsService;
        this.blockRuleService = blockRuleService;
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

    @GetMapping("/ports/summary")
    public List<Map<String, Object>> portSummary() {
        return statsService.getPortSummary();
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

    @GetMapping("/block-rules")
    public List<BlockRule> blockRules() {
        return blockRuleService.listRules();
    }

    @PostMapping("/block-rules")
    public BlockRule addBlockRule(@RequestBody Map<String, String> body) {
        try {
            return blockRuleService.addRule(body.get("keyword"));
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    @PostMapping("/block-rules/target-ip")
    public BlockRule addTargetIpBlockRule(@RequestBody Map<String, String> body) {
        try {
            return blockRuleService.addTargetIpRule(body.get("ip"));
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    @PostMapping("/block-rules/{id}/enabled")
    public BlockRule setBlockRuleEnabled(@PathVariable Long id, @RequestBody Map<String, Boolean> body) {
        try {
            return blockRuleService.setEnabled(id, Boolean.TRUE.equals(body.get("enabled")));
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage());
        }
    }

    @DeleteMapping("/block-rules/{id}")
    public Map<String, Object> deleteBlockRule(@PathVariable Long id) {
        blockRuleService.deleteRule(id);
        return Map.of("ok", true);
    }
}
