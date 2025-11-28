# WAF/RuleManager.py
"""
API endpoints để quản lý WAF rules
Sử dụng với Flask blueprint
Hỗ trợ cả JSON API và HTML dashboard tại /api/rules
"""
from flask import Blueprint, request, jsonify, render_template
import RuleEngine
import json

# Tạo Blueprint
rule_api = Blueprint('rule_api', __name__, url_prefix='/api/rules')


# ========================= HTML Dashboard =========================
@rule_api.route('/', methods=['GET'])
def get_rules():
    """
    Nếu Accept là text/html → trả HTML dashboard
    Nếu Accept là application/json → trả JSON API
    """
    accept = request.headers.get("Accept", "")
    rules_data = RuleEngine.get_all_rules()

    if "text/html" in accept:
        # Giao diện HTML
        return render_template(
            "rule_dashboard.html",
            rules=rules_data.get('rules', []),
            version=rules_data.get('version', 'unknown'),
            last_updated=rules_data.get('last_updated', 'unknown')
        )

    # Trả JSON nếu không yêu cầu HTML
    try:
        return jsonify({
            "success": True,
            "data": rules_data,
            "total": len(rules_data.get('rules', []))
        }), 200
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ========================= Stats =========================
@rule_api.route('/stats', methods=['GET'])
def get_stats():
    try:
        rules_data = RuleEngine.get_all_rules()
        rules = rules_data.get('rules', [])
        sources = {}
        attack_types = {}
        for rule in rules:
            source = rule.get('source', 'unknown')
            sources[source] = sources.get(source, 0) + 1
            attack_type = rule.get('attack_type', 'unknown')
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1

        return jsonify({
            "success": True,
            "stats": {
                "total_rules": len(rules),
                "by_source": sources,
                "by_attack_type": attack_types,
                "version": rules_data.get('version', 'unknown'),
                "last_updated": rules_data.get('last_updated', 'unknown')
            }
        }), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ========================= Search =========================
@rule_api.route('/search', methods=['GET'])
def search_rules():
    try:
        query = request.args.get('q', '').lower()
        attack_type = request.args.get('type', '').upper()
        source = request.args.get('source', '').lower()

        rules_data = RuleEngine.get_all_rules()
        rules = rules_data.get('rules', [])
        filtered = []

        for rule in rules:
            match = True
            if query:
                if query not in rule.get('name', '').lower() \
                        and query not in rule.get('pattern', '').lower() \
                        and query not in rule.get('description', '').lower():
                    match = False
            if attack_type and rule.get('attack_type', '') != attack_type:
                match = False
            if source and rule.get('source', '') != source:
                match = False
            if match:
                filtered.append(rule)

        return jsonify({
            "success": True,
            "data": filtered,
            "total": len(filtered),
            "query": {"keyword": query, "attack_type": attack_type, "source": source}
        }), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ========================= Add / Delete / Reload / Export / Import =========================
@rule_api.route('/add', methods=['POST'])
def add_rule():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No JSON data provided"}), 400

        pattern = data.get('pattern')
        name = data.get('name')
        attack_type = data.get('attack_type', 'MANUAL')
        # Lấy thêm các trường này từ request
        description = data.get('description', '')
        severity = data.get('severity', 'medium')
        source = data.get('source', 'custom')

        # Validate input cơ bản
        if not pattern or not name:
            return jsonify({"success": False, "error": "Missing required fields"}), 400

        # Gọi xuống Engine
        success = RuleEngine.add_manual_rule(
            pattern=pattern,
            name=name,
            attack_type=attack_type,
            description=description,
            severity=severity,
            source=source
        )

        if success:
            return jsonify({
                "success": True,
                "message": f"Rule '{name}' added successfully"
            }), 201
        else:
            # Có thể do trùng lặp hoặc Regex sai
            return jsonify({
                "success": False,
                "error": "Failed to add rule (Duplicate or Invalid Regex)"
            }), 400

    except Exception as e:
        print(f"[API ERROR] Add rule failed: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


# Lưu ý: Các hàm delete, reload cũng gọi RuleEngine nên sẽ hưởng lợi từ việc fix RLock.

@rule_api.route('/delete', methods=['DELETE'])
def delete_rule():
    try:
        data = request.get_json()
        pattern = data.get('pattern') if data else None
        if not pattern:
            return jsonify({"success": False, "error": "Missing pattern"}), 400

        if RuleEngine.delete_rule(pattern):
            return jsonify({"success": True, "message": "Rule deleted"}), 200
        else:
            return jsonify({"success": False, "error": "Rule not found"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@rule_api.route('/reload', methods=['POST'])
def reload_rules():
    try:
        print("[RELOAD RULES] Reloading...")
        RuleEngine.reload_rules()
        print("[RELOAD RULES] Success")
        return jsonify({"success": True, "message": "Rules reloaded successfully"}), 200
    except Exception as e:
        print(f"[RELOAD RULES] Error: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500


@rule_api.route('/export', methods=['GET'])
def export_rules():
    try:
        format_type = request.args.get('format', 'json').lower()
        rules_data = RuleEngine.get_all_rules()
        if format_type == 'json':
            return jsonify({
                "success": True,
                "data": rules_data
            }), 200
        else:
            return jsonify({"success": False, "error": "Unsupported format. Use 'json'"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@rule_api.route('/import', methods=['POST'])
def import_rules():
    try:
        data = request.get_json()
        if not data or 'rules' not in data:
            return jsonify({"success": False, "error": "Missing 'rules' array in request body"}), 400

        new_rules = data['rules']
        mode = data.get('mode', 'merge')

        if mode == 'replace':
            rules_data = {"version": "1.0", "last_updated": None, "rules": new_rules}
        else:
            rules_data = RuleEngine.get_all_rules()
            existing_patterns = {r['pattern'] for r in rules_data.get('rules', [])}
            for rule in new_rules:
                if rule.get('pattern') not in existing_patterns:
                    rules_data['rules'].append(rule)

        # Save rules
        from datetime import datetime
        rules_data['last_updated'] = datetime.now().isoformat()
        if RuleEngine.save_rules_to_json(rules_data):
            RuleEngine.reload_rules()
            return jsonify({"success": True, "message": f"Rules imported successfully ({mode} mode)",
                            "total_rules": len(rules_data['rules'])}), 200
        else:
            return jsonify({"success": False, "error": "Failed to save rules"}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ========================= Register Blueprint =========================
def register_rule_api(app):
    """
    Đăng ký Rule Management API vào Flask app
    Usage:
        from WAF.RuleManagerAPI import register_rule_api
        register_rule_api(app)
    """
    app.register_blueprint(rule_api)
    print("[RuleManagerAPI] API endpoints + HTML dashboard registered at /api/rules/")