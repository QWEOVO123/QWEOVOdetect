package org.detector.qweovodetect.stats;

import org.detector.qweovodetect.stats.model.BlockRule;
import org.detector.qweovodetect.stats.repository.BlockRuleRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Locale;
import java.net.InetAddress;

@Service
public class BlockRuleService {

    public static final String CATEGORY_DOMAIN = "DOMAIN";
    public static final String CATEGORY_TARGET_IP = "TARGET_IP";

    private final BlockRuleRepository blockRuleRepository;
    private volatile List<String> enabledKeywords = List.of();
    private volatile List<String> enabledTargetIps = List.of();

    public BlockRuleService(BlockRuleRepository blockRuleRepository) {
        this.blockRuleRepository = blockRuleRepository;
    }

    @jakarta.annotation.PostConstruct
    public void refreshCache() {
        enabledKeywords = blockRuleRepository.findByEnabledTrueOrderByCreateTimeDesc().stream()
                .filter(rule -> rule.getCategory() == null || CATEGORY_DOMAIN.equalsIgnoreCase(rule.getCategory()))
                .map(rule -> normalize(rule.getKeyword()))
                .filter(keyword -> !keyword.isBlank())
                .distinct()
                .toList();
        enabledTargetIps = blockRuleRepository.findByEnabledTrueOrderByCreateTimeDesc().stream()
                .filter(rule -> CATEGORY_TARGET_IP.equalsIgnoreCase(rule.getCategory()))
                .map(rule -> normalizeIp(rule.getKeyword()))
                .filter(ip -> !ip.isBlank())
                .distinct()
                .toList();
    }

    public List<BlockRule> listRules() {
        return blockRuleRepository.findAllByOrderByCreateTimeDesc();
    }

    @Transactional
    public BlockRule addRule(String rawKeyword) {
        String keyword = normalize(rawKeyword);
        if (keyword.length() < 2 || keyword.length() > 128) {
            throw new IllegalArgumentException("keyword length must be between 2 and 128");
        }

        BlockRule rule = blockRuleRepository.findByCategoryAndKeyword(CATEGORY_DOMAIN, keyword)
                .orElseGet(() -> new BlockRule(keyword, CATEGORY_DOMAIN));
        rule.setCategory(CATEGORY_DOMAIN);
        rule.setKeyword(keyword);
        rule.setEnabled(true);
        BlockRule saved = blockRuleRepository.save(rule);
        refreshCache();
        return saved;
    }

    @Transactional
    public BlockRule addTargetIpRule(String rawIp) {
        String ip = normalizeIp(rawIp);
        if (ip.isBlank()) {
            throw new IllegalArgumentException("请输入正确的目标 IP 地址");
        }

        BlockRule rule = blockRuleRepository.findByCategoryAndKeyword(CATEGORY_TARGET_IP, ip)
                .orElseGet(() -> new BlockRule(ip, CATEGORY_TARGET_IP));
        rule.setCategory(CATEGORY_TARGET_IP);
        rule.setKeyword(ip);
        rule.setEnabled(true);
        BlockRule saved = blockRuleRepository.save(rule);
        refreshCache();
        return saved;
    }

    @Transactional
    public void deleteRule(Long id) {
        blockRuleRepository.deleteById(id);
        refreshCache();
    }

    @Transactional
    public BlockRule setEnabled(Long id, boolean enabled) {
        BlockRule rule = blockRuleRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("rule not found"));
        rule.setEnabled(enabled);
        BlockRule saved = blockRuleRepository.save(rule);
        refreshCache();
        return saved;
    }

    public String firstMatchedKeyword(String domainOrSni) {
        String value = normalize(domainOrSni);
        if (value.isBlank()) {
            return null;
        }
        for (String keyword : enabledKeywords) {
            if (value.contains(keyword)) {
                return keyword;
            }
        }
        return null;
    }

    public boolean shouldBlock(String domainOrSni) {
        return firstMatchedKeyword(domainOrSni) != null;
    }

    public boolean shouldBlockTargetIp(String targetIp) {
        String ip = normalizeIp(targetIp);
        return !ip.isBlank() && enabledTargetIps.contains(ip);
    }

    private static String normalize(String text) {
        return text == null ? "" : text.trim().toLowerCase(Locale.ROOT);
    }

    private static String normalizeIp(String text) {
        if (text == null || text.isBlank()) {
            return "";
        }
        String value = text.trim();
        if (!value.matches("[0-9a-fA-F:.]+")) {
            return "";
        }
        try {
            return InetAddress.getByName(value).getHostAddress().toLowerCase(Locale.ROOT);
        } catch (Exception e) {
            return "";
        }
    }
}
