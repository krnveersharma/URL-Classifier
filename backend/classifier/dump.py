import lightgbm as lgb
import json

def lgb_tree_to_json(tree):
    def recurse(node):
        tree_json = {}
        if "split_index" in node:
            tree_json['type'] = 'split'
            tree_json['feature'] = node['split_feature']
            tree_json['threshold'] = node['threshold']
            tree_json['left'] = recurse(node['left_child'])
            tree_json['right'] = recurse(node['right_child'])
        else:
            tree_json['type'] = 'leaf'
            tree_json['value'] = node['leaf_value']
        return tree_json

    return recurse(tree)

def lgb_forest_to_json(model):
    forest_json = {
        'n_features': model.n_features_,
        'n_classes': len(model.classes_) if hasattr(model, 'classes_') else None,
        'classes': model.classes_.tolist() if hasattr(model, 'classes_') else None,
        'n_outputs': model._n_classes if hasattr(model, '_n_classes') else 1,
        'n_estimators': model.n_estimators_,
        'estimators': []
    }

    # Get the list of trees as dictionaries
    booster = model.booster_
    for i in range(booster.num_trees()):
        tree = booster.dump_model()['tree_info'][i]['tree_structure']
        forest_json['estimators'].append(lgb_tree_to_json(tree))

    return forest_json

# Example usage:
# from sklearn.datasets import load_iris
# X, y = load_iris(return_X_y=True)
# clf = lgb.LGBMClassifier(n_estimators=10)
# clf.fit(X, y)

# forest_json = lgb_forest_to_json(clf)
# with open('lgb_forest.json', 'w') as f:
#     json.dump(forest_json, f, indent=2)

# Example output verification
# print(json.dumps(forest_json, indent=2))
