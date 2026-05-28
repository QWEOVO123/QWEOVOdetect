package org.detector.qweovodetect.stats;

import org.detector.qweovodetect.stats.model.BlockRule;
import org.detector.qweovodetect.stats.repository.BlockRuleRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Locale;

@Service
public class BlockRuleService {

    private final BlockRuleRepository blockRuleRepository;
    private volatile List<String> enabledKeywords = List.of();

    public BlockRuleService(BlockRuleRepository blockRuleRepository) {
        this.blockRuleRepository = blockRuleRepository;
    }

    @jakarta.annotation.PostConstruct
    public void refreshCache() {
        enabledKeywords = blockRuleRepository.findByEnabledTrueOrderByCreateTimeDesc().stream()
                .map(rule -> normalize(rule.getKeyword()))
                .filter(keyword -> !keyword.isBlank())
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

        BlockRule rule = blockRuleRepository.findByKeyword(keyword)
                .orElseGet(() -> new BlockRule(keyword));
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

    private static String normalize(String text) {
        return text == null ? "" : text.trim().toLowerCase(Locale.ROOT);
    }
}
